# MAD Bugs: Discovering a radare2 0-Day in Zero Day

Command injection in radare2's PDB symbol parser. Reported as [radare2#25730](https://github.com/radareorg/radare2/issues/25730), fixed in [PR #25731](https://github.com/radareorg/radare2/pull/25731).

| File | What |
|---|---|
| [`blog.md`](blog.md) | Blog post (written by humans) |
| [`poc.py`](poc.py) | PoC |
| [`binaries/`](binaries) | Test PE + crafted PDB |
| [`radare.mov`](radare.mov) | PoC video |

## A note on the artifacts

The write-ups and PoCs in this series are AI-generated and human-verified. We keep human editing to a minimum so the artifacts document the current state of the art, which means we don't edit out hallucinations or slop. We do verify that the PoCs work. The blog posts are written by humans.
