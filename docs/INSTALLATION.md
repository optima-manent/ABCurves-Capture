# Installation

ABCurves Capture Trainer is a portable Windows x64 app. It does not install a
service and it does not upload sessions automatically.

## Release package

1. Install [USBPcap 1.5.4.0](https://desowin.org/usbpcap/) and restart Windows if
   asked.
2. Download the latest Windows ZIP from
   [GitHub Releases](https://github.com/optima-manent/ABCurves-Capture/releases).
3. Extract the complete ZIP to a normal local folder.
4. Open `ABCurves Capture Trainer.exe`.

Keep the helper executables beside the main app. Windows may ask for permission
during the initial mouse check and again when recording begins; the trainer
itself continues to run as a normal desktop app.

The current release-candidate binaries are not code-signed, so Windows may show
an unknown-publisher or reputation warning. Download only from this repository's
Releases page and use the attached `.sha256` file if you want to verify the ZIP.

## Supported connections

Use a direct USB mouse or a mouse with a USB receiver. Native Bluetooth-only
mice, PS/2 mice, and touchpads are not supported capture sources.

If a keyboard shares the receiver, its reports may appear in the raw capture.
Prefer a mouse-only receiver and avoid typing private text while a session is
running, including while the trainer is paused or in the background.

## Build from source

The complete source-build commands are in the main [README](../README.md#build-it-from-source).
