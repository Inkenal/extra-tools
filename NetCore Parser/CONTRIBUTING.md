# Contributing

Small, reviewable changes are preferred. Before adding an ETW decoder, include
a raw event fixture, its Windows build, the byte offsets, and evidence for each
field's meaning. Label unverified layouts explicitly.

Run checks locally:

```bash
python -m pip install -e . pytest
python -m pytest -q
python -m compileall -q src
```

Do not submit an interpretation based solely on a heuristic string match,
process ID reuse, or a raw-byte offset in a circular ETL. Preserve unknown
bytes rather than silently discarding them. Add regression tests for every
new parser layout, including malformed and truncated inputs.

Avoid adding frameworks, wrappers or abstractions without a concrete need.
Do not add network calls, automatic evidence deletion, or instrumentation that
changes the source computer in normal parsing mode.

