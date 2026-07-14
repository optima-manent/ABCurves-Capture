#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <windows.h>
#include <mmsystem.h>

// Optional, generated interface and target-hit sounds. Every public operation
// is best effort: a missing or failing audio device must never affect gameplay,
// event validity, capture, or session finalization.
class AudioEngine final {
public:
    enum class Sfx {
        ButtonSmall,
        ButtonLarge,
        SliderTick,
        Pop1,
        Pop2,
        Pop3,
    };

    ~AudioEngine() noexcept;

    [[nodiscard]] bool Initialize() noexcept;
    void Update() noexcept;
    void PlaySfx(Sfx sfx) noexcept;

private:
    struct SfxVoice final {
        HWAVEOUT handle = nullptr;
        WAVEHDR header{};
        std::vector<std::uint8_t> buffer;
        bool prepared = false;
        bool in_use = false;
    };

    static constexpr std::size_t kSfxCount = 6U;
    static constexpr std::size_t kSfxVoiceCount = 16U;

    void BuildGeneratedSfx();
    [[nodiscard]] bool InitializeSfxVoices();
    void CleanupFinishedSfx() noexcept;
    void StopAllSfx() noexcept;
    [[nodiscard]] SfxVoice* AcquireSfxVoice() noexcept;
    [[nodiscard]] const std::vector<std::uint8_t>& SfxPcm(Sfx sfx) const noexcept;
    static void LogFailure(const char* message) noexcept;

    std::array<std::vector<std::uint8_t>, kSfxCount> sfx_pcm_;
    std::array<SfxVoice, kSfxVoiceCount> sfx_voices_;
    std::size_t max_sfx_bytes_ = 0U;
    std::size_t next_sfx_voice_ = 0U;
    bool sfx_ready_ = false;
};
