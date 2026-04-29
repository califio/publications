# Learning to Jailbreak an iPhone with Claude

A from-the-ground-up walkthrough of **Coruna**, a leaked commercial spyware kit
targeting iOS 17: Safari to kernel, four stages, all patched. The project is to
take it apart one stage at a time, with Claude as the teacher, and write down
what it takes to actually understand each piece.

## The series

| | | |
|---|---|---|
| **Part 1** | [`Stage1-writeup.md`](Stage1-writeup.md) | CVE-2024-23222: a JavaScriptCore JIT race → `read64`/`write64` in WebContent. ~14,000 words, self-contained, no prior JIT exploitation background assumed. |
| Part 2 | (in progress) | `seedbell`: PAC bypass. R/W is not code execution on A12+; getting there without forging a pointer signature. |
| Part 3 | (planned) | Sandbox escape. |
| Part 4 | (planned) | Kernel. |

This repo carries Part 1. It walks the deobfuscated cassowary source
([`Stage1_16.6_17.2.1_cassowary-renamed.js`](Stage1_16.6_17.2.1_cassowary-renamed.js))
and explains why every line is there.

**[`poc/REPRODUCING.md`](poc/REPRODUCING.md)** is the lab manual. Build the
vulnerable JSC, run the PoC, see `read64`/`write64` land on your own machine.

## Reproduce

You need an Apple Silicon Mac with full Xcode (not CommandLineTools). The
WebKit clone is ~640MB with `--filter=blob:none`; the build takes about ten
minutes for the `jsc` shell or 1-2 hours for MiniBrowser.

```bash
# 1. build vulnerable jsc (see poc/REPRODUCING.md for the long version)
git clone --filter=blob:none https://github.com/WebKit/WebKit.git jsc-vuln/WebKit
git -C jsc-vuln/WebKit checkout WebKit-7617.1.17.13.7
jsc-vuln/WebKit/Tools/Scripts/build-jsc --release

# 2. point jsc at the local framework instead of the system one (one-time)
install_name_tool -change \
  /System/Library/Frameworks/JavaScriptCore.framework/Versions/A/JavaScriptCore \
  @executable_path/JavaScriptCore.framework/Versions/A/JavaScriptCore \
  jsc-vuln/WebKit/WebKitBuild/Release/jsc
codesign -f -s - jsc-vuln/WebKit/WebKitBuild/Release/jsc

# 3. run
jsc-vuln/WebKit/WebKitBuild/Release/jsc poc/cve-2024-23222-rw.js
```

A hit prints `[+] ALL TESTS PASSED. Arbitrary read/write achieved.` The race
is one shot per process; `poc/retry-race.sh` wraps the relaunch loop.
Reliability tracks system load (the race window is comparable to OS scheduler
jitter on the compiler thread's wake-up); on an idle M-series machine it's
~89%.

The race is between two FTL compiler passes and a main-thread structure
transition. The window is fixed in compiler-thread time, but the aim point
(`PIVOT`, the loop iteration where `delete target.p2` fires) is in main-thread
time. Different hardware has a different exchange rate. If your hit rate is
low, sweep `PIVOT`; the comments at the top of `cve-2024-23222-rw.js` explain
how to read which side of the window you're on.

Linux ARM64 works with the same procedure; see `REPRODUCING.md`.

## Repo map

```
Stage1-writeup.md                      the article
Stage1_16.6_17.2.1_cassowary-renamed.js  deobfuscated source the article walks
images/                                SVGs the article inlines
poc/
  cve-2024-23222-rw.js                 canonical PoC: addrof → fakeobj → r/w
  cve-2024-23222-rw-browser.html       same, in a Worker, for MiniBrowser
  REPRODUCING.md                       build & run details
  README.md                            what every other file in poc/ is for
  retry-race.sh                        relaunch-until-hit wrapper
  build-webkit-browser.sh              full-WebKit build (MiniBrowser)
  run-minibrowser-poc.sh               DYLD plumbing for the browser PoC
  dfg-race-widen.patch                 JSC patch: deterministic replay
  tgcp-instrumentation.patch           JSC patch: tgcp ring buffer
  ftl-disasm-{safe,buggy}.log          the disasm the article quotes
coruna-main.zip                        raw capture: all stages, all iOS versions
```

`coruna-main.zip` is the unmodified leak as captured, copied from
[khanhduytran0/coruna](https://github.com/khanhduytran0/coruna)
(jacurutu/terrorbird/cassowary Stage 1, seedbell Stage 2, VariantB Stage 3).
Everything in `poc/` was rebuilt clean-room from reading `cassowary.js`;
nothing is copied across.

## What this is not

Not weaponized. No PAC bypass, sandbox escape, or kernel stage. The PoC
demonstrates `read64`/`write64` against your own JSC build and stops there.
The bug was patched in January 2024 and has been public since.

## A note on the artifacts

The write-ups and PoCs in this series are AI-generated and human-verified. We keep human editing to a minimum so the artifacts document the current state of the art, which means we don't edit out hallucinations or slop. We do verify that the PoCs work. The blog posts are written by humans.

`Stage1-writeup.md` is the one exception in this directory: it is joint work by humans and AI.

## Acknowledgments

Builds on RE work by Huy Nguyen, wh1te4ever, Duy Tran, Nathan, hrtowii,
Nick Chan, and the wider jailbreak community.
