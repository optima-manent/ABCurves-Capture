# Contributing

Contributions are welcome. If you are planning a larger change, open an issue or
join the [Discord](https://discord.gg/Nyf272vUjz) first so we can compare notes.

A few ideas guide the project:

- Keep the original USB and gameplay records intact. Smoothing, clipping, event
  selection, and model-specific transforms belong in offline tools.
- Treat Raw Input as the responsive gameplay input and USBPcap as the recorded
  hardware stream; they do not need to produce identical batches.
- Keep failures local when possible. A sound, focus, or rendering issue should
  not discard an otherwise healthy capture.
- Do not add usernames, serial numbers, native device paths, or unrelated device
  traffic to session metadata.
- Add a focused test for changes to capture, recovery, timing, or data formats.

Before opening a pull request:

```powershell
cmake --preset windows-x64
cmake --build --preset release
ctest --preset release
```

For hardware-related changes, mention the Windows version, USBPcap version,
mouse/receiver type, connection, and polling rate you tested. Please use
synthetic or scrubbed fixtures rather than uploading a participant session.
