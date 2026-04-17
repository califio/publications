# MAD Bugs: Even `cat readme.txt` is not safe

In a previous post about MAD bugs in [Vim and Emacs](https://blog.calif.io/p/mad-bugs-vim-vs-emacs-vs-claude), we looked at how seemingly harmless workflows could cross a surprising line into code execution. This time we wanted to push that idea even further: is `cat readme.txt` safe?

It turns out that it is NOT, if you use iTerm2.

PoC video: https://youtu.be/J-CyOJcKXwg

This bug starts with a simple claim: in iTerm2, a malicious file can trigger arbitrary code execution when the victim runs:

```sh
cat readme.txt
```

That sounds insane until you understand what iTerm2 is trying to do for a legitimate feature, how it uses the PTY, and what happens when terminal output is able to impersonate one side of that feature's protocol.

>We'd like to acknowledge OpenAI for partnering with us on this project.

## Background: iTerm2's SSH integration

iTerm2 has an SSH integration feature that gives it a richer understanding of remote sessions. To make that work, it does not just "blindly type commands" into a remote shell. Instead, it bootstraps a tiny helper script on the remote side called the conductor.

The rough model is:

1. iTerm2 launches SSH integration, usually through `it2ssh`.
2. iTerm2 sends a remote bootstrap script, the conductor, over the existing SSH session.
3. That remote script becomes the protocol peer for iTerm2.
4. iTerm2 and the remote conductor exchange terminal escape sequences to coordinate things like:
   - discovering the login shell
   - checking for Python
   - changing directories
   - uploading files
   - running commands

The important point is that there is no separate network service. The conductor is just a script running inside the remote shell session, and the protocol is carried over normal terminal I/O.

## PTY refresher

A terminal used to be a real hardware device: a keyboard and screen connected to a machine, with programs reading input from that device and writing output back to it.

A terminal emulator like iTerm2 is the modern software version of that hardware terminal. It draws the screen, accepts keyboard input, and interprets terminal control sequences.

But the shell and other command-line programs still expect to talk to something that looks like a real terminal device. That is why the OS provides a PTY, or pseudoterminal. A PTY is the software stand-in for the old hardware terminal, and it sits between the terminal emulator and the foreground process.

In a normal SSH session:

- iTerm2 writes bytes to the PTY
- the foreground process is `ssh`
- `ssh` forwards those bytes to the remote machine
- the remote conductor reads them from its stdin

So when iTerm2 wants to "send a command to the remote conductor," what it actually does locally is write bytes to the PTY.

## The conductor protocol

The SSH integration protocol uses terminal escape sequences as its transport.

Two pieces matter here:

- `DCS 2000p` is used to hook the SSH conductor
- `OSC 135` is used for pre-framer conductor messages

At source level, `DCS 2000p` causes iTerm2 to instantiate a conductor parser. Then the parser accepts `OSC 135` messages like:

- `begin <id>`
- command output lines
- `end <id> <status> r`
- `unhook`

So a legitimate remote conductor can talk back to iTerm2 entirely through terminal output.

## The core bug

The bug is a trust failure.

iTerm2 accepts the SSH conductor protocol from terminal output that is not actually coming from a trusted, real conductor session. In other words, untrusted terminal output can impersonate the remote conductor.

That means a malicious file, server response, banner, or MOTD can print:

- a forged `DCS 2000p` hook
- forged `OSC 135` replies

and iTerm2 will start acting like it is in the middle of a real SSH integration exchange. That is the exploit primitive.

## What the exploit is really doing

The exploit file contains a fake conductor transcript.

When the victim runs:

```sh
cat readme.txt
```

iTerm2 renders the file, but the file is not just text. It contains:

1. a fake `DCS 2000p` line that announces a conductor session
2. fake `OSC 135` messages that answer iTerm2's requests

Once the hook is accepted, iTerm2 starts its normal conductor workflow. In upstream source, `Conductor.start()` immediately sends `getshell()`, and after that succeeds it sends `pythonversion()`.

So the exploit does not need to inject those requests. iTerm2 issues them itself, and the malicious output only has to impersonate the replies.

## Walking the state machine

The fake `OSC 135` messages are minimal but precise.

They do this:

1. Start a command body for `getshell`
2. Return lines that look like shell-discovery output
3. End that command successfully
4. Start a command body for `pythonversion`
5. End that command with failure
6. Unhook

This is enough to push iTerm2 down its normal fallback path. At that point, iTerm2 believes it has completed enough of the SSH integration workflow to move on to the next step: building and sending a `run(...)` command.

## Where `sshargs` comes in

The forged `DCS 2000p` hook contains several fields, including attacker-controlled `sshargs`.

That value matters because iTerm2 later uses it as command material when it constructs the conductor's `run ...` request.

The exploit chooses `sshargs` so that when iTerm2 base64-encodes:

```text
run <padding><magic-bytes>
```

the last 128-byte chunk becomes:

```text
ace/c+aliFIo
```

That string is not arbitrary. It is chosen because it is both:

- valid output from the conductor encoding path
- a valid relative pathname

## The PTY confusion that makes exploitation possible

In a legitimate SSH integration session, iTerm2 writes base64-encoded conductor commands to the PTY, and `ssh` forwards them to the remote conductor. In the exploit case, iTerm2 still writes those commands to the PTY, but there is no real SSH conductor. The local shell receives them as plain input instead.

That is why the session looks like this when recorded:

- `getshell` appears as base64
- `pythonversion` appears as base64
- then a long base64-encoded `run ...` payload appears
- the last chunk is `ace/c+aliFIo`

Earlier chunks fail as nonsense commands. The final chunk works if that path exists locally and is executable.

## Steps to reproduce

You can reproduce the original file-based PoC with `genpoc.py`:

```sh
python3 genpoc.py
unzip poc.zip
cat readme.txt
```

This creates:

- `ace/c+aliFIo`, an executable helper script
- `readme.txt`, a file containing the malicious `DCS 2000p` and `OSC 135` sequences

The first fools iTerm2 into talking to a fake conductor. The second gives the shell something real to execute when the final chunk arrives.

For the exploit to work, run `cat readme.txt` from the directory containing `ace/c+aliFIo`, so the final attacker-shaped chunk resolves to a real executable path.

## Disclosure timeline

- Mar 30: We reported the bug to iTerm2.
- Mar 31: The bug was fixed in commit `a9e745993c2e2cbb30b884a16617cd5495899f86`.
- At the time of writing, the fix has not yet reached stable releases.

When the patch commit landed, we tried to rebuild the exploit from scratch using the patch alone. The prompts used for that process are in [`prompts.md`](https://github.com/califio/publications/tree/main/MADBugs/iTerm2/prompts.md), and the resulting exploit is `genpoc2.py`, which works very similarly to `genpoc.py`.
