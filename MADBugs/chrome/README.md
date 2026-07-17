# Journey to Root, Episode I: The Maglev King

Writeup and proof-of-concept code for the first episode of *Journey to Root*, an
AI-assisted Chrome exploitation series. Episode I covers the **renderer
compromise**: turning two V8 bugs into native code execution inside Chrome's
renderer process, entirely from JavaScript.

The full chain in the series is 5 vulnerabilities (renderer plus GPU process) and earned US$117,000 in the Chrome Vulnerability Reward Program. This episode is the renderer half of it.

## Target

| | |
|---|---|
| V8 version | `14.6.202.33` |
| Commit | [`f09a912`](https://chromium.googlesource.com/v8/v8/+/f09a91282a26caa91d016c962d785d852cfdec36) |
| Chrome for Testing | `146.0.7680.208` (x64) |
| Demo OS | Windows 11 x64, Build 26200.8457 |

## Contents

| Path | What it is |
|------|------------|
| [`episode1.md`](episode1.md) | The writeup. Act I is the Maglev bug and trigger; Act II is the JSPI sandbox escape; the final section maps everything onto the full Windows PoC. |
| [`poc/`](poc/) | All proof-of-concept code, with its own [`README.md`](poc/README.md) covering how to build `d8` and run each script. |
| [`images/`](images/) | Figures used in the writeup. |

## Running the PoCs

See [`poc/README.md`](poc/README.md) for the full instructions. In short:

* [`poc/poc.html`](poc/poc.html) is the complete renderer exploit. It runs only on
  the pinned Chrome for Testing 146 build on Windows x64 and pops `notepad.exe` as
  proof of native code execution.
* [`poc/poc0.js`](poc/poc0.js) through [`poc/poc3.js`](poc/poc3.js) and
  [`poc/primitives/`](poc/primitives/) are the cross-platform pieces for following
  along in Act I: the trigger and the four primitives, runnable on a `d8` you
  build yourself (Linux or macOS, x64 or arm64) at the commit above.

## Disclosure

All bugs were reported to Google and fixed before publication. The full timeline
is at the end of [`episode1.md`](episode1.md).
