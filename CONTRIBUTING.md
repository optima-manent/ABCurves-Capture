# Contributing

Changes should preserve the separation between authoritative capture, gameplay,
and offline derivation.

- Never make Raw Input/USB equality a session-liveness condition.
- Write selected endpoint source bytes before attempting HID decode.
- Keep focus and presentation failures local to the active event.
- Treat queue loss, device identity change, framing loss, corruption, and
  storage failure as destructive.
- Put smoothing, clipping, event selection, seam choice, and model-specific
  validation in versioned offline adapters.
- Do not persist native device paths, serial numbers, container IDs, account
  information, or unrelated endpoint traffic.

Run the Release build and full CTest suite before submitting a change. Add a
contract test for every scientific, recovery, or failure-policy change. Hardware
changes also require the relevant scenarios in `docs/TESTING.md`.
