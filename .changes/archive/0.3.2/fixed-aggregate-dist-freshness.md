---
kind: fixed
summary: the aggregate verification gate now rejects stale committed build output
---

`npm run verify` now fails when source and committed `dist/` disagree instead
of packing a build that exists only in the local working tree.
