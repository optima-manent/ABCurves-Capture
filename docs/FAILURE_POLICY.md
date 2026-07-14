# Failure policy

The collector distinguishes destructive failures, local event interruptions,
and diagnostic uncertainty.

## Destructive: stop or safely pause collection

- USBPcap helper/process/owner channel is lost.
- The certified physical device is removed, replaced, or changes its locked
  root/address identity.
- Native capture queue overflows, bytes are discarded, or the PCAP parser loses
  framing.
- The authoritative raw capture/event writer or a required flush fails, free
  space becomes unsafe, or finalized raw files fail integrity checks.
- The process cannot establish that the selected device address is still being
  captured after an explicit transport failure.

The app stops gameplay, drains what it can, and preserves the verified prefix as
an interrupted session. It never deletes otherwise readable source evidence.
Published capture files are parsed end to end before they are called verified;
framing, device bus/address identity, and record counts are
recomputed from disk rather than trusted from a helper status message.

## Recoverable: affect one event or interval

- Alt-Tab, focus loss, minimize, display transition, a temporary loss of the
  selected Windows gameplay-input handle, or manual pause.
- Target presentation failure or graphics-device recreation.
- Participant-interface rendering failure.
- Sleep/resume.

Capture remains active. The active event is labelled/discarded, the challenge
clock freezes, and play resumes with a fresh event boundary.

Optional hit-sound initialization or playback failure is even narrower: the
sound is dropped without changing the event, challenge clock, capture, or
session status.

## Diagnostic: record and continue

- Raw Input/USB delivery, batching, total, or timing disagreement.
- Other physical mouse activity.
- Clock-fit residual, PCAP timestamp regression, or wall-clock step when source
  framing remains intact.
- A failed/empty USB transfer, duplicate-looking payload, unknown report ID, or
  logical decode failure whose raw PCAP record was preserved.
- Missing or failed decoded-report, anomaly, sound, or interface derivatives.
- Polling-rate variation, frame stall, late event join, or a missing optional
  witness.

Diagnostics add typed annotations and may make an event ineligible for a
particular adapter. They do not end a healthy raw capture.

## Finalization

Finalization always attempts to publish readable source evidence. A session can
be `complete`, `complete_with_warnings`, `interrupted`, or `capture_lost`; these
are acquisition states, not ML suitability claims. A recovery archive also
states whether a verified authoritative PCAP prefix exists. Each exporter
independently chooses events and intervals according to its versioned policy.

After a process crash, the next launch acquires an exclusive session lease
before recovery. Complete framed records are retained, only torn tails are
trimmed, invalid bytes are preserved for organizer review, and gameplay never
resumes inside the recovered session. A writer that still holds the lease is
left unchanged.
