# Feeding Claude Phrack Articles for Fun and Profit: Desync the Planet

Reproducing — and extending — the Phrack 72 *Desync the Planet* rsync RCE chain (CVE-2024-12085 + CVE-2024-12084) with Claude.

| File | What |
|---|---|
| [`blog.md`](blog.md) | Blog post (written by humans) |
| [`writeup.md`](writeup.md) | Technical write-up of the x86-64 build |
| [`writeup2.md`](writeup2.md) | Technical write-up of the ARM64 port and audit follow-up |
| [`exploit.py`](exploit.py) | x86-64 exploit |
| [`exploit2.py`](exploit2.py) | ARM64 exploit |
| [`rsync_lib.py`](rsync_lib.py) | Custom rsync protocol library used by `exploit.py` |
| [`rsync_lib2.py`](rsync_lib2.py) | Variant used by `exploit2.py` |
| [`rsyncd_test.conf`](rsyncd_test.conf) | Test daemon config |

## A note on the artifacts

The write-ups and PoCs in this series are AI-generated and human-verified. We keep human editing to a minimum so the artifacts document the current state of the art, which means we don't edit out hallucinations or slop. We do verify that the PoCs work. The blog posts are written by humans.
