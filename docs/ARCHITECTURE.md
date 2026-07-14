# Architecture

## Design objective

The collector has three independent lanes. They meet through append-only source
records and explicit timestamps, not through live equality gates.

```text
capture lane (elevated helper)
  USBPcap address filter -> exact-device PCAP -> optional decoded reports
        |                         |                         |
        +-- health/anomalies -----+-------------------------+

gameplay lane (normal user)
  Raw Input -> virtual count camera -> targets/outcomes/pause annotations

offline join lane
  USB reports + event QPC + clock anchors + render transform
      -> event segments -> 1 kHz telemetry -> ABCurves/downstream adapters
```

Capture health, gameplay state, and event usability are different types. No
component may convert a diagnostic difference in one lane into data loss in
another lane.

## Capture lane

Only the bounded probe and capture helpers are elevated. Capture filters the
selected USB address in the driver and persists the complete exact-address
stream. This preserves the rich raw evidence needed to decode unusual mice
offline. A shared receiver may therefore include sibling keyboard/media
traffic from that same physical USB device; the consent screen discloses this.

The helper first appends every exact-device PCAP record losslessly. Decoding is
a second, optional operation. Successful logical HID reports are appended to
`mouse_reports.abcr2`; a failed/unknown report stays in PCAP and produces a structured
anomaly. Decoder uncertainty degrades the affected span rather than erasing the
source bytes.

The native reader uses bounded queues and accounts for every delivered byte. A
successful zero-byte USBPcap completion is normal both while active (nothing is
available) and after `STOP_FILTERING` (a valid quiet edge). Parser framing loss,
queue overflow, discarded bytes, device loss, or a storage failure is
destructive and stops capture.

There are no scientific block checkpoints. Writers flush periodically and at
lifecycle boundaries. Capture and journal streams are framed so organizer-side
recovery code can verify and trim incomplete tails. Before publication, the
participant process re-reads the complete device PCAP and checks every record's
bus/address against the certified mouse. Present derivatives are checked
independently; missing or failed derivatives become metadata, not raw-data loss.

The participant and elevated capture helper independently hold a shared OS
session lease. Startup recovery must acquire that lease exclusively before it
can inspect or change a `.partial` workspace. It then trims only incomplete
framed tails, preserves invalid bytes under explicit `.unverified` names,
validates all capture/gameplay/clock records, seals the session without
resuming gameplay, and independently validates its submission archive. Normal
finalization retains its shared lease through the sealed-directory rename, ZIP
creation, and independent archive validation. A live participant or stuck
helper therefore cannot race recovery. A process crash after the sealed-directory
rename but before ZIP publication is repaired on the next launch by recreating
the missing archive from the immutable validated session.

Archive creation streams each immutable artifact through standard ZIP Deflate.
Empty, incompressible, or compressor-failed members fall back to ZIP's stored
method without changing their bytes. The candidate archive is written under a
unique `.partial` name, durably flushed, fully extracted into a private temporary
directory, checked by CRC and the sealed-session SHA-256 inventory, and only then
atomically published. The validator also accepts the legacy all-stored archives.

A valid PCAP header proves framing only. A header-only file is preserved for
review but has `verified_authoritative_source=false`; at least one validated
record from the certified device address is required for an authoritative prefix.

## Device certification

Discovery begins with the participant-selected Raw Input physical mouse and
joins it to one PnP/USB physical device and USBPcap root/address. Descriptor
reconstruction and endpoint enumeration are retained when available, but are
not capture eligibility requirements.

One bounded move-and-click probe requires movement and a full click from the
selected Windows mouse while a live USBPcap interrupt stream changes. During
this check only, the elevated helper observes the selected root because the
address reported by Windows hub topology can disagree with USBPcap's live
packet address on otherwise healthy machines. It retains bounded counters and
change state in memory, returns no USB payloads, and writes no broad-root PCAP.
The winning live address is then used as the exact kernel filter for the entire
recording. Decoder-derived correlation can select a useful report stream, but
cannot veto that physical-device proof. Raw Input message counts and USB report
counts are never expected to be equal. The probe has a finite result; retry is
an explicit participant action rather than an automatic loop.

The required lock contains root, live address, and a privacy-safe physical-
device token. Interface, endpoint, descriptor hash, and decoder specification
are optional capabilities. A changed or removed locked device is destructive.
Activity from an unrelated mouse is not.

## Gameplay lane

Raw Input drives the centered-crosshair virtual camera because it is available
to the normal-user UI with low latency. Every Raw Input message is optionally
recorded with its receipt QPC and device classification, but it is labelled as
a witness.

The trainer owns one challenge schedule and one target generator. Target truth
is authored in count space. Each event records target generation provenance,
absolute and spawn-relative geometry, the exact render transform, submission
and successful-presentation QPC, resolution input, outcome, and post-resolution
tail.

Successful presentation starts an event; it does not require a motionless guard.
Movement between submission and first presentation is simply outside that event.
Movement after presentation remains part of the event.

Protocol v3 renders every timed fading target with continuous alpha over its
playable lifetime and adds 60 ms to both the fade and timeout. Keeping those two
deadlines identical prevents an invisible-but-clickable or visible-but-expired
target. The Quick Test selects one block from each challenge and changes only
the block duration to 10 seconds; the manifest records that actual plan.

Focus loss, Alt-Tab, minimize, display transition, or manual pause freezes the
challenge clock, labels the active event as a technical discard, releases mouse
capture, and leaves the USB helper running. Return to the window starts a short
resume countdown and a fresh event boundary. Earlier events remain untouched.

Rendering has its own recoverable boundary. An exception, device loss, or a
target that cannot be presented promptly retires the pending/active event and
pauses gameplay while the renderer is recreated. Generated hit sounds are
best-effort and exception-contained; they never alter event or session state.

## Offline join lane

USBPcap timestamps are host-side USB/URB observation timestamps. Gameplay uses
QPC. Repeated `(QPC, precise UTC)` anchors quantify their mapping. Alignment
residuals and wall-clock steps become uncertainty intervals; they do not rewrite
native timestamps or invalidate the raw session.

The implemented interchange exporter derives consecutive 1 ms mouse bins,
flat event/block tables, clock fits, and quality masks. It deliberately chooses
no continuation cut or smoothing policy. Because raw reports and lifecycle
boundaries are retained, future ABCurves and other seam builders can remain
separate, versioned downstream adapters.

## Ownership and dependency direction

```text
platform/base <- capture primitives <- elevated helper
platform/base <- device discovery  <- certification
platform/base <- trainer domain    <- normal-user app/UI
capture + trainer + clocks         <- session recorder/finalizer
immutable session                  <- validators/exporters/replay
```

The trainer domain has no USBPcap, filesystem, renderer, or Win32 dependency.
The capture core has no gameplay dependency. UI code projects state and sends
commands; it does not own scientific invariants.
