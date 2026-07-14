# Installing the participant package

ABCurves Capture Trainer is distributed as a portable Windows x64 ZIP. It does
not install a service and it never uploads data automatically.

1. Install USBPcap 1.5.4.0 from its
   [official distribution](https://desowin.org/usbpcap/) and restart Windows if
   its installer requests it.
2. Download the Windows x64 ZIP from the
   [ABCurves Capture releases](https://github.com/optima-manent/ABCurves-Capture/releases)
   page and extract it to a normal local folder. Do not run the application from
   inside the ZIP and do not separate the executable files.
3. Open `ABCurves Capture Trainer.exe`.
4. Windows may ask for permission during the bounded mouse check and again when
   collection starts. Each helper launch prompts at most once and is never
   retried automatically. The trainer itself remains a normal-user process.

The capture path supports a direct USB mouse or a mouse using a USB receiver.
A native Bluetooth-only mouse, PS/2 mouse, or touchpad is not a supported data
source. Prefer a mouse-only receiver. If a keyboard shares the receiver, its
key reports can be included in the raw selected-device capture; do not type
passwords, messages, or other private text while the session is running.

Version 0.4.1 release-candidate executables are not Authenticode signed. Windows
may therefore show an unknown-publisher or reputation warning. Only use the ZIP
from the project's GitHub Releases page and compare its SHA-256 with the
attached `.sha256` file before running it. Code signing is strongly recommended
before broad participant distribution.

Keep `abct_capture_helper.exe` and, when present, `abct_probe_helper.exe` beside
the participant application. `abct_session_tool.exe` is an offline validation
utility. `abct_research_export.exe` creates the organizer-side research
interchange. Both may be left in the same folder.

The package includes `BUILD_INFO.json` and `SHA256SUMS`. Study organizers can
use `scripts/Test-ReleasePackage.ps1` from the source repository to verify the
archive, its inventory, its x64 executables, and the command-line tools before
distribution.
