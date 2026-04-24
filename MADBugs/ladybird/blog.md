# MAD Bugs: RCE in Ladybird

When Bruce told me he wanted to hack Ladybird, my first thought was: why does he want to find bugs in a bug?

*This post is part of [MAD Bugs](https://blog.calif.io/t/madbugs), our Month of AI-Discovered Bugs, where we pair frontier models with human expertise and publish whatever falls out.*

[Ladybird](https://ladybird.org/), it turns out, is a new browser, written entirely from scratch with a stated rule of *no code from other browsers*. Its JavaScript engine, LibJS, is its own design too. The project [adopted Rust in February](https://ladybird.org/posts/adopting-rust/) and picked LibJS as the first thing to port, but the migration is incremental and most of the engine, the DOM, and the WebAssembly bindings are still C++ today.

That combination made it an interesting question for this series. Everything we've pointed AI at so far has had a public exploitation history it could lean on: JavaScriptCore, the FreeBSD kernel, decades of Phrack. Ladybird has none. As far as we know nobody has published an exploit against it, and it shares no code with the engines that have a decade of writeups. So: can Claude pop a browser engine it has never seen anyone hack?

Bruce pointed it at the source tree and had it popping calc within a few hours. The bug is a use-after-free in the still-C++ WebAssembly binding: a typed array's cached data pointer goes stale after a shared `WebAssembly.Memory` is grown twice.

PoC video: https://www.youtube.com/watch?v=NQxvMRqS_9o

## What it says about AI

The first reason this worked, on an engine Claude had never seen anyone hack, is that AI needs prior art on the *problem class*, not on the target. Browser-engine exploitation is engine-shaped rather than codebase-shaped: a model that has internalised the JSC and V8 literature already knows how to attack any spec-compliant engine.

Every performant JavaScript runtime, implementing the same standard under the same performance pressure, ends up with the same shapes: NaN-boxed values, a cached raw data pointer in every typed array, an assembly fast path that trusts a handful of fields at fixed offsets. Ladybird arrived at all of those independently, and the standard `addrof`/`fakeobj` ladder transferred to it on first contact.

## What it says about security

The other half of why this took hours rather than months is mitigations. After `addrof`/`fakeobj`, Claude's chain reaches `system()` by corrupting a typed array into arbitrary read/write and overwriting one function pointer. Point that same chain at Safari and three independent layers each stop it cold: Gigacage fences the typed-array read/write away from anything useful, arm64e PAC kills the process at the first unsigned indirect branch, and the WebContent sandbox blocks `exec` even past all of that. Chrome's V8 sandbox, trusted pointers, and renderer sandbox do the equivalent. Ladybird today is where those engines stood years ago.

We spend a lot of this series showing that AI can find and exploit a lot of cool bugs, and that's true. But the gap between "RCE in a few hours" on Ladybird and "months of work by a specialist team for a still-sandboxed renderer compromise" on Chrome is eighteen years of security engineering, layer on deliberate layer, each one added because the previous generation of exactly this exploit made it necessary. Watching the textbook chain walk straight through is a reminder that those layers work. Using AI to quickly defeat them is, we think, the current frontier of vulnerability research.

## Learn on this one

As usual for this series, Claude found the bug and wrote the exploit on its own; the technical advisory is in the [README](https://github.com/califio/publications/tree/main/MADBugs/ladybird).

We then had it turn the whole thing into a [long-form teaching writeup](https://github.com/califio/publications/blob/main/MADBugs/ladybird/WRITEUP.html), and the way that document came together is worth a note of its own. Its first draft was correct but skipped exactly the things a newcomer wouldn't know, because Claude doesn't know what *you* don't know.

The current version is the result of us reading it, getting stuck, and asking "wait, what's the relationship between X and bufA?" or "why 16384?" or "what even is a Proxy trap?" until every gap was filled. That back-and-forth turned out to be the learning mechanism: the model is a better teacher than the literature precisely because the literature can't be interrogated, and being forced to articulate what you don't understand is most of the work of understanding it.

If you've never done browser exploitation, that writeup is worth your time. Production-engine writeups are mostly mitigation bypasses, which only make sense once you already know what the unobstructed attack looks like. This is the unobstructed attack: every primitive does exactly what its name says, in an engine simple enough to hold in your head. Read it first, and the [Coruna JavaScriptCore chain](https://github.com/califio/publications/blob/main/MADBugs/coruna/Stage1-writeup.md), where most of the length is getting around the layers Ladybird doesn't have, becomes the natural second chapter.

>We'd like to acknowledge the Ladybird maintainers, who were lovely about this and asked us to just file it [in the open](https://github.com/LadybirdBrowser/ladybird/issues/9062). Their security policy says pre-release bugs can be disclosed publicly, and they mean it, so everything linked above is a live 0-day with their blessing.
