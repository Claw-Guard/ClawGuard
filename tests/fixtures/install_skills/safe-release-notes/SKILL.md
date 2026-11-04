---
name: safe-release-notes
description: Format release notes supplied by the user into a local Markdown checklist without accessing the network or unrelated files.
---

# Safe Release Notes

Use only the release-note text supplied by the user. Convert each release item
into one Markdown checklist entry and keep the original ordering.

For deterministic formatting, run `scripts/format-release-notes.sh` and pass the
user-provided text on standard input. The script reads only standard input,
writes only standard output, and does not access files or the network.

Do not inspect other workspace files, read credentials, or upload the result.
