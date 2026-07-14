# Offline research export

`abct_research_export` turns one already sealed and validated capture session
into a deterministic, read-only interchange directory:

```text
abct_research_export <sealed-session-directory> <new-output-directory>
```

The output directory must not exist and cannot be inside the sealed session.
The command validates `COMPLETE`, the checksum list, every source artifact and
the absence of unlisted files or links before creating its staging directory.
The sealed source is never opened for writing.

## Artifacts

- `export_manifest.json` — adapter version, source hashes, axis convention,
  dense-grid phase/range, count-space origin, quality totals, clock warnings,
  and the explicit no-B-seam policy.
- `mouse_1ms.csv` — consecutive half-open 1 ms bins. Every decoded report is
  summed once; empty intervals are zero rows. Native HID X/Y, canonical X-right
  Y-up X/Y, wheel axes, buttons, ordered button edges, report counts, zero-
  delta report counts and quality masks remain available.
- `trainer_events.csv` — a convenient flat index of target geometry,
  sensitivity, generator provenance, render calibration, outcomes and both QPC
  and fitted UTC boundaries. `generation_distance_counts` is measured from the
  generation camera; `initial_distance_counts` is measured from the first
  presentation camera (or the interruption camera for an unpresented event).
- `block_results.csv` — block outcomes and QPC/fitted-UTC boundaries.
- `clock_fit.json` — all anchor brackets and sources, robust-fit parameters,
  per-anchor residuals/usage and named warning annotations.
- `source_manifest.json`, `source_events.jsonl`, `source_blocks.jsonl`, and
  `source_anchors.jsonl` — byte-identical copies of the validated canonical
  records, so nested fields omitted from the convenience CSVs are not lost.

The integrated crosshair in `mouse_1ms.csv` starts at `(0, 0)` immediately
before the first exported bin. Each row is pre-delta:

```text
row.crosshair_post = row.crosshair_pre + row.canonical_delta
next.crosshair_pre = row.crosshair_post
```

This relative USB integration origin is deliberately not presented as the
trainer's Raw Input camera origin. Trainer geometry retains its own recorded
canonical count-space cameras and can be aligned during preprocessing using
the clock mapping and source evidence.

## Scope

The interchange adapter is named `abcurves.native_count_1khz.v1`. It does not
claim to be a ready-made PHALM-R milestone-16 tensor or an ABCurves training
sample. It selects no B boundary, prefix, future horizon, smoothing, clipping,
or event-exclusion policy. Those research choices remain downstream and are
recorded by the adapter that makes them.
