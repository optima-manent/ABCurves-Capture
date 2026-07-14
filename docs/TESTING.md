# Testing and hardware qualification

Automated tests establish deterministic data and failure-policy contracts. They
cannot prove that a particular USB controller, mouse firmware, receiver, or
USBPcap installation behaves correctly. A public study build must pass both the
automated suite and the hardware matrix below.

## Automated suite

```powershell
cmake --preset windows-x64
cmake --build --preset release
ctest --preset release
```

The contract executable covers capture framing, exact-device filtering, HID report
decoding, tolerant certification, helper lifecycle, trainer modes, pause/resume,
source journals, crash recovery, clock fitting, 1 ms derivation, sealed-session
integrity, OS-held writer leases, exact device-address revalidation,
automatic abandoned-session recovery, and deterministic submission archives.
It also covers Deflate round trips, stored-member fallback, material compression,
and rejection of malformed compressed streams. It locks the 10-second Quick Test
duration and every grace-extended fading target lifetime.

Warnings from an optional witness or a fit-quality metric must never be turned
into a test assertion that destroys otherwise preserved source data.

## Required manual scenarios

Run each scenario with a fresh session and validate the resulting directory and
ZIP with `abct_session_tool validate`.

| Scenario | Expected behavior |
| --- | --- |
| Normal full run | Capture remains healthy; every completed block and raw exact-device record is sealed. |
| Alt-Tab during a target | Trainer pauses, the current event is technically discarded, capture continues, and resume uses a countdown. |
| Repeated focus cycles | Earlier events remain unchanged; no retry/stillness prompt appears. |
| Manual pause during a tail | The natural outcome remains recorded; the tail is marked interrupted. |
| Other mouse moves | Selected-mouse session continues; detailed unrelated Raw Input packets are not persisted. |
| Selected mouse unplugged | Gameplay stops, the verified capture prefix is recovered and sealed as `capture_lost`. |
| Helper terminated | Gameplay stops and publishes the longest verified prefix. |
| Disk becomes unwritable/full | Collection stops without claiming a clean completion; already durable bytes remain. |
| App killed during recording | Next launch acquires the abandoned lease, trims only torn tails, seals without resuming, and creates a reviewable archive. |
| App killed after session seal | Next launch recreates and validates the missing `_SEND_THIS.zip` from the immutable sealed directory. |
| Second collector is still writing | Startup recovery reports an active session and leaves every file untouched. |
| Startup scan during normal ZIP finalization | The participant lease blocks recovery until the archive has passed independent validation. |
| ZIP opened with Windows Explorer/PowerShell | Standard extraction succeeds and every extracted session checksum validates. |
| PCAP contains only its global header | Evidence is archived with zero records and is never labelled an authoritative prefix. |
| Sleep/resume or display reset | Active event is discarded or annotated; prior events and capture remain. |
| Quick Test | Exactly one block per challenge runs for 10 seconds; the HUD shows the selected-plan position. |
| Fading target families | Fade is continuous; tickle reset, precision big, precision small, and fast flicker remain playable for 330, 460, 510, and 510 ms respectively. |
| Sound device unavailable | Hit feedback is silent; gameplay, USB capture, and finalization continue. |
| Renderer/UI failure during a target | Only that event is technically discarded; challenge time pauses and USB capture continues through renderer recovery. |
| UAC denied | One concise permission result is shown; no automatic UAC loop occurs. |
| Descriptor/endpoint decoding unavailable | Move-and-click certification and raw collection succeed; decoded reports are marked unavailable. |
| Windows topology address differs from live USBPcap address | The bounded check selects the dominant changing interrupt stream; recording then uses only that exact observed address. |
| Timestamp regression/decode failure | Source PCAP remains, anomaly is recorded, and later valid reports are decoded. |

## Hardware matrix

Qualify combinations rather than only mouse brands:

- Windows 10 and Windows 11, current x64 release builds;
- Intel and AMD USB host controllers;
- direct ports and representative USB 2/USB 3 hubs;
- wired mice and 2.4 GHz receivers;
- simple mice and composite receivers with keyboard/media interfaces;
- 125, 250, 500, 1000, 2000, 4000, and 8000 Hz modes where available;
- report-ID and no-report-ID descriptors;
- 8-bit, 12/16-bit, and batched movement reports where available;
- three-button, extra-button, vertical-wheel, and horizontal-wheel devices;
- multiple simultaneously connected mice.

Record for each run: Windows build, USBPcap version, controller/hub class, mouse
and connection class, configured report rate, certification method, descriptor
hash, session status, capture counters, warnings, validation result, and archive
SHA-256. Do not record serial numbers or native device paths.

## Public release gate

A candidate is suitable for public collection only when:

1. Release configuration builds from a clean checkout and all automated tests pass.
2. The packaged normal-user app launches each sibling helper with at most one
   UAC prompt and never relaunches one automatically.
3. At least one simple wired mouse, one high-rate mouse, and one composite
   wireless receiver complete the manual scenarios.
4. Packet/queue byte accounting is exact for every run. A loss event must stop
   and preserve the prefix rather than claim success.
5. ZIP and directory validation independently pass, and extraction contains no
   unlisted file. Shared-receiver traffic disclosed by the consent screen is
   retained only within the selected physical USB device address.
6. PHALM-R milestone-16 adapter parity fixtures pass for axis, 1 ms bin phase,
   pre-delta integration, and continuation-cut conventions.
7. A full routine at the highest qualified report rate has a measured worst-case
   session size, and the startup/free-space thresholds leave enough margin to
   finish and seal it without wasting a participant run.
8. The distribution has an Authenticode signing plan, or the unsigned Windows
   reputation-warning flow and external release SHA-256 verification have been
   participant-tested and documented for the exact candidate.

Decode warnings, clock residuals, polling variation, and Raw Input/USB timing
differences are not release failures when the selected raw source is intact and
the uncertainty is represented honestly.
