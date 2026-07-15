# ABCurves Capture Trainer

<p align="center">
  <strong>An aim trainer for collecting rich, hardware-level mouse data.</strong>
</p>

<p align="center">
  <a href="https://github.com/optima-manent/ABCurves-Capture/releases"><strong>Download</strong></a>
  ·
  <a href="https://discord.gg/Nyf272vUjz"><strong>Join the Discord</strong></a>
  ·
  <a href="https://optima-manent.github.io/ABCurves/"><strong>ABCurves live demo</strong></a>
</p>

ABCurves Capture Trainer combines a Windows aim trainer with USBPcap capture.
While someone plays, it records the selected mouse's raw USB traffic alongside
targets, clicks, timing, and game results. The result is a portable research
session that can be checked, archived, and processed later without throwing away
the original data.

The project is designed for collecting data across different computers, mice,
USB controllers, polling rates, and play styles. It is the data-collection
companion to [ABCurves](https://github.com/optima-manent/ABCurves).

## Get it

### Download the Windows release

The easiest option is the portable ZIP on the
[Releases page](https://github.com/optima-manent/ABCurves-Capture/releases).

1. Install [USBPcap 1.5.4.0](https://desowin.org/usbpcap/) and restart Windows if
   asked.
2. Download and extract `ABCurves-Capture-Trainer-*-windows-x64.zip`.
3. Open `ABCurves Capture Trainer.exe`.

The trainer supports direct USB mice and mice connected through a USB receiver.
Native Bluetooth-only mice, PS/2 mice, and touchpads are not capture sources.

### Build it from source

You will need Windows 10 or 11 x64, Visual Studio 2022 Build Tools with the
Desktop C++ workload, CMake 3.25 or newer, and USBPcap for live capture.

```powershell
git clone https://github.com/optima-manent/ABCurves-Capture.git
cd ABCurves-Capture
cmake --preset windows-x64
cmake --build --preset release
ctest --preset release
```

The app will be at:

```text
build\windows-x64\Release\ABCurves Capture Trainer.exe
```

To build the same portable ZIP used for releases:

```powershell
cmake --preset windows-x64 -DABCT_ENABLE_PACKAGING=ON
cmake --build --preset release
cmake --build build/windows-x64 --config Release --target abct_package
```

The verified ZIP is written to `build/windows-x64/package`.

## Using the trainer

1. Choose the physical mouse you want to record.
2. Complete a short move-and-click check so the app can find the matching USB
   stream.
3. Pick your sensitivity and presentation settings.
4. Run the full routine or use Quick Test for a shorter pass.
5. Let the app finish saving. The file ending in `_SEND_THIS.zip` is the session
   to keep or share with the research organizer.

Alt-Tab, focus loss, and manual pause stop the gameplay clock without stopping
the underlying capture. If the app is interrupted, the next launch attempts to
recover and package the completed part of the session.

## What gets recorded

- Raw USBPcap records from the selected mouse or USB receiver
- Decoded mouse reports when the device format can be understood
- Target positions, clicks, outcomes, timing, and pause/focus events
- Clock anchors, device information, checksums, and capture-quality notes

The original PCAP and gameplay records are the source data. Dense 1 ms tables or
model-specific inputs are produced later, so preprocessing can change without
having to recollect the session.

The app saves locally and never uploads on its own. Participants decide whether
to share the final ZIP. If a keyboard shares the selected USB receiver, its key
reports may also be present in the raw PCAP; use a mouse-only receiver when
possible and avoid typing private text during a session. See
[Privacy](docs/PRIVACY.md) for the full, plain-language summary.

## Research tools

Validate a returned session directory or ZIP:

```powershell
.\build\windows-x64\Release\abct_session_tool.exe validate <path>
```

For optional manual QA, the extraction-free Python inspector can open or accept
a dropped `_SEND_THIS.zip`, replay each event's authoritative mouse path, and
save reviewer notes beside the ZIP:

```powershell
python .\tools\inspect_capture_session.py <session_SEND_THIS.zip>
```

The inspector is a viewing aid, not a replacement for organizer-side safety and
pool-admission validation.

Create a deterministic 1 ms research export from a completed session:

```powershell
.\build\windows-x64\Release\abct_research_export.exe <session-directory> <output-directory>
```

The exporter keeps native mouse counts, canonical count-space fields, buttons,
wheels, empty time bins, target events, outcomes, settings, and clock-fit
information. The sealed source session is left unchanged.

## Join in

This is where the next stage of the ABCurves research effort is happening, and
I'd be glad for company.

Play with the [ABCurves live demo](https://optima-manent.github.io/ABCurves/) and
compare the movements yourself. Join the
[Discord](https://discord.gg/Nyf272vUjz) to ask questions, share test results,
report how the trainer behaves with your setup, reach me directly, or
collaborate. New mouse formats, better diagnostics, stronger validation, and
useful research adapters are all welcome.

## Documentation

- [Installation](docs/INSTALLATION.md)
- [Participant guide](docs/USER_GUIDE.md)
- [Privacy](docs/PRIVACY.md)
- [Data format](docs/DATA_CONTRACT.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Testing and hardware coverage](docs/TESTING.md)
- [Research export](docs/RESEARCH_EXPORT.md)
- [Building releases](docs/RELEASING.md)

## License

Project code is available under the [MIT License](LICENSE). Vendored components
keep their original licenses; see [Third-party notices](THIRD_PARTY_NOTICES.md).
