#include "audio/AudioEngine.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <vector>

namespace {

constexpr int kSampleRate = 44'100;
constexpr double kPi = 3.14159265358979323846;

WAVEFORMATEX SfxWaveFormat() noexcept {
    WAVEFORMATEX format{};
    format.wFormatTag = WAVE_FORMAT_PCM;
    format.nChannels = 1;
    format.nSamplesPerSec = kSampleRate;
    format.wBitsPerSample = 16;
    format.nBlockAlign = static_cast<WORD>(
        (format.nChannels * format.wBitsPerSample) / 8);
    format.nAvgBytesPerSec = format.nSamplesPerSec * format.nBlockAlign;
    return format;
}

std::vector<std::uint8_t> ToPcmBytes(
    const std::vector<std::int16_t>& samples) {
    std::vector<std::uint8_t> bytes(samples.size() * sizeof(std::int16_t));
    if (!bytes.empty()) {
        std::memcpy(bytes.data(), samples.data(), bytes.size());
    }
    return bytes;
}

std::vector<std::int16_t> MakeSweep(const double duration_seconds,
                                    const double start_hz,
                                    const double end_hz,
                                    const double gain,
                                    const double decay,
                                    const double harmonic_mix) {
    const int sample_count = std::max(
        1, static_cast<int>(duration_seconds * kSampleRate));
    std::vector<std::int16_t> samples;
    samples.reserve(static_cast<std::size_t>(sample_count));

    double phase = 0.0;
    for (int index = 0; index < sample_count; ++index) {
        const double time = static_cast<double>(index) / kSampleRate;
        const double progress = duration_seconds > 0.0
            ? time / duration_seconds
            : 0.0;
        const double frequency = start_hz + (end_hz - start_hz) * progress;
        phase += (kPi * 2.0 * frequency) / kSampleRate;

        const double attack = std::min(1.0, time / 0.0015);
        const double release = std::clamp(
            (duration_seconds - time) / 0.006, 0.0, 1.0);
        const double envelope = attack * release * std::exp(-decay * time);
        const double click = std::exp(-120.0 * time) *
            std::sin(phase * 5.0);
        const double wave = std::sin(phase) +
            harmonic_mix * std::sin(phase * 2.0) + 0.28 * click;
        const double value = std::clamp(wave * envelope * gain, -1.0, 1.0);
        samples.push_back(static_cast<std::int16_t>(value * 32'767.0));
    }
    return samples;
}

}  // namespace

AudioEngine::~AudioEngine() noexcept {
    StopAllSfx();
}

bool AudioEngine::Initialize() noexcept {
    try {
        BuildGeneratedSfx();
        sfx_ready_ = InitializeSfxVoices();
        return sfx_ready_;
    } catch (...) {
        StopAllSfx();
        LogFailure("Generated sound initialization failed; sound is disabled.\n");
        return false;
    }
}

void AudioEngine::Update() noexcept {
    CleanupFinishedSfx();
}

void AudioEngine::PlaySfx(const Sfx sfx) noexcept {
    try {
        const auto& pcm = SfxPcm(sfx);
        if (!sfx_ready_ || pcm.empty()) return;

        SfxVoice* voice = AcquireSfxVoice();
        if (voice == nullptr) return;

        std::fill(voice->buffer.begin(), voice->buffer.end(), std::uint8_t{0});
        const std::size_t copy_size = std::min(voice->buffer.size(), pcm.size());
        if (copy_size > 0U) {
            std::memcpy(voice->buffer.data(), pcm.data(), copy_size);
        }

        if (waveOutWrite(voice->handle, &voice->header,
                         sizeof(voice->header)) != MMSYSERR_NOERROR) {
            voice->in_use = false;
            LogFailure("Sound playback failed; this sound was skipped.\n");
            return;
        }
        voice->in_use = true;
    } catch (...) {
        LogFailure("Sound playback failed; this sound was skipped.\n");
    }
}

void AudioEngine::BuildGeneratedSfx() {
    sfx_pcm_[0] = ToPcmBytes(
        MakeSweep(0.045, 980.0, 1320.0, 0.18, 34.0, 0.25));
    sfx_pcm_[1] = ToPcmBytes(
        MakeSweep(0.075, 520.0, 920.0, 0.26, 24.0, 0.35));
    sfx_pcm_[2] = ToPcmBytes(
        MakeSweep(0.032, 1480.0, 1180.0, 0.13, 50.0, 0.10));
    sfx_pcm_[3] = ToPcmBytes(
        MakeSweep(0.086, 260.0, 182.0, 0.34, 24.0, 0.16));
    sfx_pcm_[4] = ToPcmBytes(
        MakeSweep(0.092, 294.0, 204.0, 0.32, 22.0, 0.14));
    sfx_pcm_[5] = ToPcmBytes(
        MakeSweep(0.080, 233.0, 165.0, 0.36, 26.0, 0.18));

    max_sfx_bytes_ = 0U;
    for (const auto& pcm : sfx_pcm_) {
        max_sfx_bytes_ = std::max(max_sfx_bytes_, pcm.size());
    }
}

bool AudioEngine::InitializeSfxVoices() {
    StopAllSfx();
    if (max_sfx_bytes_ == 0U) return false;

    const WAVEFORMATEX format = SfxWaveFormat();
    std::size_t ready_voice_count = 0U;
    for (SfxVoice& voice : sfx_voices_) {
        voice.buffer.assign(max_sfx_bytes_, std::uint8_t{0});
        voice.header = {};
        voice.header.lpData = reinterpret_cast<LPSTR>(voice.buffer.data());
        voice.header.dwBufferLength =
            static_cast<DWORD>(voice.buffer.size());

        if (waveOutOpen(&voice.handle, WAVE_MAPPER, &format, 0, 0,
                        CALLBACK_NULL) != MMSYSERR_NOERROR) {
            voice.handle = nullptr;
            continue;
        }
        if (waveOutPrepareHeader(voice.handle, &voice.header,
                                 sizeof(voice.header)) != MMSYSERR_NOERROR) {
            waveOutClose(voice.handle);
            voice.handle = nullptr;
            continue;
        }
        voice.prepared = true;
        ++ready_voice_count;
    }

    if (ready_voice_count == 0U) {
        LogFailure("No sound device was available; sound is disabled.\n");
    }
    return ready_voice_count > 0U;
}

void AudioEngine::CleanupFinishedSfx() noexcept {
    for (SfxVoice& voice : sfx_voices_) {
        if (voice.in_use && (voice.header.dwFlags & WHDR_DONE) != 0U) {
            voice.in_use = false;
        }
    }
}

void AudioEngine::StopAllSfx() noexcept {
    for (SfxVoice& voice : sfx_voices_) {
        if (voice.handle != nullptr) {
            waveOutReset(voice.handle);
            if (voice.prepared) {
                waveOutUnprepareHeader(voice.handle, &voice.header,
                                       sizeof(voice.header));
            }
            waveOutClose(voice.handle);
        }
        voice = SfxVoice{};
    }
    sfx_ready_ = false;
    next_sfx_voice_ = 0U;
}

AudioEngine::SfxVoice* AudioEngine::AcquireSfxVoice() noexcept {
    CleanupFinishedSfx();
    for (std::size_t attempt = 0U; attempt < sfx_voices_.size(); ++attempt) {
        const std::size_t index =
            (next_sfx_voice_ + attempt) % sfx_voices_.size();
        SfxVoice& voice = sfx_voices_[index];
        const bool queued = (voice.header.dwFlags & WHDR_INQUEUE) != 0U;
        if (voice.handle != nullptr && voice.prepared && !voice.in_use &&
            !queued) {
            next_sfx_voice_ = (index + 1U) % sfx_voices_.size();
            return &voice;
        }
    }
    return nullptr;
}

const std::vector<std::uint8_t>& AudioEngine::SfxPcm(
    const Sfx sfx) const noexcept {
    const auto index = static_cast<std::size_t>(sfx);
    return sfx_pcm_[index < sfx_pcm_.size() ? index : 0U];
}

void AudioEngine::LogFailure(const char* const message) noexcept {
    OutputDebugStringA("[audio] ");
    OutputDebugStringA(message);
}
