# MAD Bugs: All Your Reverse Engineering Tools Are Belong to US

> **Subtitle:** Ghidra, IDA Pro, radare2, and Binary Ninja Sidekick. If your tool doesn't show up here, it's not cool enough. Contact us for a free RCE.

Two weeks ago we told you about how we used AI to find a [radare2 0-day](https://blog.calif.io/p/mad-bugs-discovering-a-0-day-in-zero), and the day after that, an [auth bypass in NSA's Ghidra Server](https://blog.calif.io/p/mad-bugs-claude-found-an-auth-bypass) that has been hiding in plain sight since 2019.

Some of you were, understandably, skeptical and unimpressed. Maybe AI got lucky.

So here are four more. All arbitrary code execution, all in the tools you actually use, all discovered with Claude or Codex. And if this still doesn't move you, well, it's OK. Denial is coping, we've been there.

| Target | Status | Bug |
|---|---|---|
| **IDA Pro** | Embargoed | |
| **Binary Ninja Sidekick** | Embargoed | |
| **radare2** | [Fixed upstream](https://github.com/radareorg/radare2/issues/25752) | PDB section-header command injection (survives the #25731 fix) |
| **Ghidra** | Reported, details below | RMI deserialisation RCE via novel Jython 2.7.4 gadget |

## IDA Pro & Binary Ninja Sidekick

These two are under disclosure with Hex-Rays and Vector 35 respectively. We'll publish full details, PoCs, and our prompt logs when the embargoes lift.

What we *can* say:

- Both are arbitrary code execution.
- Both trigger on the normal "open the thing someone sent you" workflow.

https://youtu.be/WxWw4dSxMCQ
https://youtu.be/u2QaSAySqjw

## radare2

When we [reported the first radare2 PDB injection](https://blog.calif.io/p/mad-bugs-discovering-a-0-day-in-zero), the fix landed the same day: base64-encode the symbol name before interpolating it into the `fN` command.

Except `print_gvars()` interpolates *two* attacker-controlled fields into RAD-mode output, and the fix only touched one of them. Four lines above the patched `fN` line, the raw 8-byte PE **section header name** still goes into the `f` command via `%.*s` with no sanitization at all:

```c
pdb->cb_printf ("f pdb.%s = 0x%" PFMT64x " # %d %.*s\n",
    filtered_name, ..., PDB_SIZEOF_SECTION_NAME,
    sctn_header->name);          // <-- still raw from the binary
```

Stick a `\n` in the section name and the `#` comment ends; whatever follows is a fresh r2 command. The catch is you only get 7 bytes per line — but a [HITCON CTF 2017 "BabyFirst Revenge"](https://github.com/orangetw/My-CTF-Web-Challenges#babyfirst-revenge)-style stager turns 7-byte writes into arbitrary-length `sh` execution. Two days after the first report, [#25752](https://github.com/radareorg/radare2/issues/25752) went in and was fixed immediately.

The radare2 team turns around fixes faster than anyone else in this post. However, **incomplete fixes are a bug class of their own**, and AI is unreasonably good at finding them. It read the patch for #25731, asked "what *else* gets interpolated here?", and had a working PoC before we'd finished debating the merit of AI vulnerability research on X.

PoC video: https://www.youtube.com/watch?v=W7Jnp9AH-OU

[Full writeup + `poc.py` →](https://github.com/califio/publications/tree/main/MADBugs/radare2-pdb-section-rce)

## Ghidra

This is NSA's tool, open-sourced in 2019, and now the default free reverse-engineering suite for most of the malware analysts, CTF players, and embedded reverse engineers who aren't paying for IDA.

This is also the one we want to spend time on, because the bug is simple but the exploit is genuinely fun.

### The bug, in three sentences

Ghidra Server installs an `ObjectInputFilter` allow-list at startup so a malicious *client* can't send it deserialisation gadgets. The Ghidra *client* installs no such filter, so a malicious *server* can send the client whatever it wants. And opening a `.gpr` project file silently connects to whatever `ghidra://` URL is sitting in its `projectState` XML — no prompt, no URL shown, nothing.

So: hand someone a Ghidra project, they double-click it, your server answers the very first RMI call (`reg.list()`, before any auth handshake) with a gadget chain instead of a `String[]`, and `Runtime.exec()` fires on their box.

```java
// ServerConnectTask.java — first thing the client does
Registry reg = LocateRegistry.getRegistry(server.getServerName(),
    server.getPortNumber(), new SslRMIClientSocketFactory());
checkServerBindNames(reg);          // → reg.list() → readObject() with NO filter
```

"Java RMI deserialisation" usually means "go grab a chain from ysoserial." However, the only fat jar on the default Ghidra client classpath is `jython-standalone-2.7.4.jar`, and Jython 2.7.4 specifically patched the classic ysoserial `Jython1` chain by adding a `readResolve()` tripwire to `PyFunction`.

So we asked AI to go looking for another `Serializable` + `InvocationHandler` in the same jar, and found one the Jython devs missed: **`org.python.core.PyMethod`**. The chain wires `PyMethod.__func__` to the package-private `BuiltinFunctions` table at `index=18` — which is `__builtin__.eval` — and feeds it a `PyBytecode` object. `PyBytecode` is Jython's *CPython 2.7 opcode interpreter*, and serialises cleanly. The payload is **21 bytes of CPython bytecode** that pulls `java.lang.Runtime` out of `co_consts` and calls `exec`.

```
PriorityQueue.readObject
  └─ siftDownUsingComparator
    └─ Proxy(Comparator).compare      ← PyMethod is the InvocationHandler
      └─ PyMethod.__call__
        └─ BuiltinFunctions[18]       ← __builtin__.eval
          └─ eval(PyBytecode, g, l)
            └─ CPython 2.7 interpreter
              └─ Runtime.getRuntime().exec({"/bin/sh","-c",CMD})
```

A Java deserialisation chain that bottoms out in a Python bytecode VM. We think that's a first.

The victim sees one error dialog *after* the calculator has already popped — `PySingleton cannot be cast to Integer`, which is just `PriorityQueue` being confused about what it got back. By then it doesn't matter.

PoC video: youtube.com/watch?v=KXFTbr43HQo

This one took real work. Building the gadget, hand-writing an SSL-wrapped JRMP responder that lies on `reg.list()`, getting the project skeleton to pass `isOwner`. The kind of thing that would normally eat a researcher-week. AI did the gadget search, the bytecode assembly, and the JRMP protocol speaking; we did the swearing at Docker.

[Full writeup →](https://github.com/califio/publications/tree/main/MADBugs/ghidra-rmi-rce)

This affects every Ghidra release ≥ 9.1. The fix is the obvious one: install the same serial filter on the client that already ships for the server. We've sent a patch.

And yes, we're aware we just dropped a 0-day on an NSA product (again!). Relax, disclosure cops. If they're half as good at this as everyone says, they already knew. We're just bringing the rest of you up to speed.

---

*The MAD Bugs series runs through April 2026. Full index at [blog.calif.io/t/madbugs](https://blog.calif.io/t/madbugs) and [github.com/califio/publications](https://github.com/califio/publications/tree/main/MADBugs).*
