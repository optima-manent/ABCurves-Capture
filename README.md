# ABCurves Capture Trainer

ABCurves Capture Trainer is a Windows aim trainer and research-data collector.
It records one participant-selected mouse through USBPcap, records target and
gameplay truth on the same host timeline, and preserves enough source evidence
to build PHALM-R, ABCurves, and future datasets offline.

The core rule is simple: USBPcap is movement truth. Windows Raw Input provides
low-latency gameplay control and an optional witness. A timing or batching
difference between them can annotate an interval, but it cannot kill a healthy
USB capture.

## Download and run

Participants should use the portable Windows x64 ZIP from the
[GitHub Releases page](https://github.com/optima-manent/ABCurves-Capture/releases),
not a source-code archive.

1. Install [USBPcap](https://desowin.org/usbpcap/) and restart Windows if its
   installer requests it.
2. Download and fully extract the newest
   `ABCurves-Capture-Trainer-*-windows-x64.zip` release.
3. Open `ABCurves Capture Trainer.exe` and follow the on-screen mouse check.
4. When a run finishes, keep the clearly named `_SEND_THIS.zip` file for the
   study organizer.

The trainer does not install a service, require an account, or upload anything
automatically. See the [installation guide](docs/INSTALLATION.md),
[participant guide](docs/USER_GUIDE.md), and [privacy summary](docs/PRIVACY.md)
before distribution.

Use a direct USB mouse or a mouse with a USB receiver; native Bluetooth-only
mice are not supported by USBPcap. If a keyboard shares the selected receiver,
its key reports can be present in the raw capture, so prefer a mouse-only
receiver and do not type private text during a session.

## Project status

Version 0.4.1 is the first release candidate from this clean replacement for the
earlier coupled collector. Its capture, trainer, session, recovery, integrity,
and offline 1 ms contracts are covered by hardware-free tests. A candidate must
also pass the real-hardware acceptance matrix in
[docs/TESTING.md](docs/TESTING.md) before it is used for public study collection.

## Participant experience

1. Read the short privacy summary and choose the physical USB mouse. On launch,
   any earlier interrupted local session is safely finished first; active
   writers are never touched.
2. Complete one bounded move-and-click check so the selected USB stream is
   certified before collection.
3. Choose sensitivity, optional crosshair/highlight/hit-sound feedback, and
   either the full routine or a Quick Test with 10 seconds per challenge.
4. Start the trainer and play.
5. Alt-Tab, minimize, or focus loss pauses gameplay while USB capture continues.
   Only the affected event is technically discarded.
6. On completion, keep or send the clearly named `_SEND_THIS.zip` archive.

There are no stillness rituals, exact Raw Input reconciliation boundaries,
polling-rate gates, or automatic retry loops.

Timed targets fade continuously and remain playable through a 60 ms grace
extension. Interface and optional sound failures are presentation problems,
not capture failures: sound feedback is simply skipped, while an unavailable
target presentation retires only that event and pauses for graphics recovery.

## Source-of-truth layers

- `capture/mouse_usb.pcap`: every original USBPcap record from the certified
  physical USB device address, including all endpoints and transfer types.
- `capture/mouse_reports.abcr2`: successfully decoded logical HID reports with
  exact payloads and transport provenance.
- `capture/capture_anomalies.jsonl`: failed transfers, decode uncertainty, and
  other nonfatal capture observations.
- `gameplay/events.jsonl`: complete target geometry, presentation, outcome, and
  post-resolution tail records in QPC time.
- `gameplay/raw_input_witness.jsonl`: optional Windows input witness, explicitly
  marked non-authoritative.
- `clocks/anchors.jsonl`: bracketed QPC and precise-UTC anchors for offline
  alignment.
- `manifest.json`, `checksums.sha256`, and `COMPLETE`: versioned metadata and a
  complete integrity inventory.

Before a session is called authoritative, the finalized device PCAP is parsed
again end to end and every record is checked against the certified bus/address.
ABCRPT2 and anomaly derivatives are independently checked when present, but
their absence or validation failure cannot invalidate preserved raw data.
Existence or checksum publication alone is not treated as source verification.

Dense 1 kHz telemetry and Planner/Renderer tensors are derived adapters. They
never decide whether source evidence is allowed to survive.

## Research lineage

This collector is the data-acquisition companion to
[ABCurves](https://github.com/optima-manent/ABCurves). It deliberately retains
raw USB evidence and explicit target/gameplay truth rather than committing the
capture app to one training pipeline. The offline research exporter supplies a
deterministic 1 ms interchange for PHALM-R milestone 16, ABCurves, and future
preprocessing experiments while leaving the sealed source session unchanged.

## Build

Requirements:

- Windows 10 or 11 x64
- Visual Studio 2022 Build Tools with the Desktop C++ workload
- CMake 3.25 or newer
- USBPcap 1.5.4.0 installed for real hardware capture

```powershell
cmake --preset windows-x64
cmake --build --preset release
ctest --preset release
```

The build produces the normal-user participant application, the bounded mouse-
check and capture helpers, the session validation/archive tool, the offline
research exporter, and the tested libraries. The app is built by default and
can be disabled with `-DABCT_BUILD_APP=OFF` for library-only work.

Validate a returned session directory or archive with:

```powershell
.\build\windows-x64\Release\abct_session_tool.exe validate <path>
```

Submission files are ordinary ZIPs using standard Deflate compression. Archive
creation never rewrites the sealed source directory: it creates a temporary ZIP,
extracts and validates every source checksum, and atomically publishes the
`_SEND_THIS.zip` only after that independent round trip succeeds.

Create a deterministic, dense 1 ms research interchange from a sealed session
with:

```powershell
.\build\windows-x64\Release\abct_research_export.exe <sealed-session-directory> <new-output-directory>
```

This interchange preserves source/native and canonical count fields, buttons,
wheels, empty bins, targets, outcomes, sensitivity, and clock-fit evidence. It
is an auditable preprocessing boundary, not a claim that the files are already
PHALM-R milestone 16 tensors.

## Architecture

The runtime has independent capture, gameplay, and offline-derivation lanes.
They meet through append-only records and explicit clocks rather than live
equality checks. Only the bounded mouse-check and capture helpers are elevated;
the participant UI and trainer run normally.

The gameplay behavior follows the original PHALM-R aim trainer. Count-space and
continuation contracts follow PHALM-R milestone 16 and ABCurves. Audited
USBPcap/HID primitives were retained from the superseded collector, while its
coupled preflight, reconciliation, retry, and checkpoint machinery was removed.

See:

- [Architecture](docs/ARCHITECTURE.md)
- [Data contract](docs/DATA_CONTRACT.md)
- [Failure policy](docs/FAILURE_POLICY.md)
- [Privacy](docs/PRIVACY.md)
- [Testing and hardware qualification](docs/TESTING.md)
- [Building and publishing releases](docs/RELEASING.md)

## License

Project code is released under the [MIT License](LICENSE). Vendored and external
components retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
