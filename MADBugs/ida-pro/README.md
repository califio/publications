# IDA Pro RCE via Clang Argument Injection

A malicious `.i64` database file can inject arbitrary arguments into IDA's built-in `clang` type parser via the `CLANG_ARGV` netnode. By using `-MD -MF -MT`, an attacker plants a Python file in IDA's plugin directory, which executes as arbitrary code the next time the victim opens IDA.

Fixed in [IDA 9.3sp2](https://docs.hex-rays.com/release-notes/9_3sp2) by restricting `CLANG_ARGV` to an allowlist of safe flag prefixes.

| File | What |
|---|---|
| [`blog.md`](blog.md) | Blog post (written by Claude) |
| [`prompts.md`](prompts.md) | Full prompt log |
| [`poc/build_poc.py`](poc/build_poc.py) | PoC: builds a malicious `.i64` that drops a Python plugin on parse |

## A note on the artifacts

The write-ups and PoCs in this series are AI-generated and human-verified. We keep human editing to a minimum so the artifacts document the current state of the art, which means we don't edit out hallucinations or slop. We do verify that the PoCs work.
