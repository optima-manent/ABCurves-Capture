# Data contract

Contract family: `abcurves.capture.session.v2`.

The current trainer mechanics are identified as
`abcurves.capture-trainer.protocol-v3`. Protocol v3 records a 60 ms playable
grace on every fading target and records the selected block duration (60 seconds
for Full Research or 10 seconds for Quick Test) in the session plan.

This is a source-evidence contract. Dense telemetry, validation grades, and ML
tensors are derived views and must name their own adapter/version.

The `_SEND_THIS.zip` is a transport wrapper, not part of the scientific schema.
Standard ZIP Deflate changes only the transport representation; extraction must
reproduce every listed session artifact byte-for-byte and pass the session's
SHA-256 inventory. Stored members and legacy all-stored archives remain valid.

## Coordinate space

The selected device report is preserved unchanged in source evidence. A
versioned adapter derives the canonical form:

```text
device_delta = [hid_dx, hid_dy]       # usually X right, Y down
canonical_delta = [hid_dx, -hid_dy]   # X right, Y up
```

The source report retains native counts and exact payload; exports retain both
native and canonical representations plus the named transform. Counts are never
multiplied by DPI, Windows pointer settings, acceleration, or trainer
sensitivity. Wheel and button fields are retained where the descriptor exposes
them; the exact payload always remains available.

Targets, crosshair positions, and radii use canonical count-equivalent units.
Every presentation records viewport dimensions and the exact linear render
mapping (`pixels_per_count` and its inverse). Sensitivity is locked for a run,
stored as metadata, and its effect on the render mapping is explicit.

## Time domains

Every USB record retains its original PCAP seconds/fraction/resolution and
derived signed Unix nanoseconds. Records also retain strictly increasing local
sequence numbers. PCAP time is not described as firmware generation or
electrical-bus time.

Gameplay lifecycle records use QPC ticks and store the session QPC frequency.
Periodic clock anchors contain QPC, precise UTC nanoseconds, capture source, and
measurement ordering. Offline mapping reports uncertainty rather than changing
either source timestamp.

## USB source records

For every PCAP record from the selected physical USB device address, preserve:

- original PCAP timestamp, included/original length, and payload bytes;
- USBPcap IRP id, status, function, info/direction, bus, device, endpoint,
  transfer kind, declared payload length, and request/completion role;
- capture/parser sequence and truncation/drop diagnostics;
- for successful decodes: report id, batch index/count, signed X/Y, wheel,
  buttons, exact logical-report payload, and decoder identity;
- for unsuccessful decodes: structured error and the unchanged source record.

Zero-delta reports, multiple logical reports per transfer, empty periods, failed
transfers, and repeated payloads remain distinguishable.

## Gameplay source records

Each target/event has stable session, participant, event, block, and target-
ordinal identifiers. The manifest identifies the plan; target provenance also
retains its bounded generation-attempt number. Participant IDs are
pseudonymous grouping keys and are never model features.

Record at minimum:

- challenge/task type and target-generator seed/draw provenance;
- target absolute center, spawn-relative center, scalar radius, visibility,
  timeout/fade/dwell/tail policy, sensitivity, and render mapping;
- target submission, first successful presentation, event start, resolution,
  tail end, and pause/discard QPC boundaries;
- generation-time distance in the nested realized target and presentation-time
  distance in the event wrapper (both are retained when movement occurs before
  the first rendered target frame);
- pre/post movement click hypotheses when applicable, dwell completion,
  closest-point and closest-swept distances, score eligibility, and explicit
  natural versus technical outcomes;
- natural outcome string (`hit_click`, `hit_dwell`, `miss_click`, `timeout`, or
  `challenge_end_timeout`) plus a separate technical-discard outcome;
- focus/capture lifecycle records and linked typed quality annotations.

Events extend through their post-resolution observation tail when available.
A focus loss can end only the affected event; it cannot remove earlier events or
the surrounding raw USB stream.

## Derived 1 kHz telemetry

The offline interchange exporter bins all decoded USB reports into consecutive
half-open 1 ms intervals and sums every report in a bin. Empty bins are explicit
zero rows; a USB report is never treated as equivalent to one millisecond.

It emits a dense mouse table plus separate event, block, and clock tables.
Together they retain the timestamps and provenance required for a downstream
join, but this exporter does not materialize event/task labels onto every 1 ms
row. Native and canonical deltas, pre-delta integrated crosshair, target
geometry, clicks, outcomes, sensitivity, report counts, and uncertainty masks
remain available across those tables. Dense bins span the first through last
decoded USB report; quiet padding to event/session boundaries is a downstream
policy. The export identifies itself as an interchange view, not as a direct
model-ready tensor.

The integration invariant is:

```text
crosshair[t + 1] = crosshair[t] + canonical_mouse_delta[t]
```

## Continuation adapters

Source capture and the implemented interchange exporter do not choose a B seam.
A future downstream adapter must define and record its cut timestamp/tick and
convention. Different edge and continuation conventions can coexist under
versioned adapter identifiers because they are all derivable from the same
report and event timeline.

Likewise, NPZ prefix/future arrays, masks, smoothing, clipping, progress, speed,
and acceleration are downstream products, not artifacts currently emitted by
this repository.
