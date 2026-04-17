# iTerm2: Arbitrary Code Execution via SSH Integration Escape Sequences

## Summary

A remote attacker can execute arbitrary commands on a victim's machine by having them `cat` a file in iTerm2. The attack exploits the DCS 2000p SSH conductor protocol and OSC 135 responses, none of which check `terminalIsTrusted`. The conductor base64-encodes a `run` command and writes it to the shell's stdin. By crafting sshargs so the base64 output's last 128-byte chunk equals a relative path (`ace/c+aliFIo`) pointing to a planted executable, the shell executes attacker-controlled code.

## Detail

1. **DCS 2000p** (`VT100DCSParser.m:527`) activates the SSH conductor hook. No `terminalIsTrusted` check.

2. The conductor's state machine sends commands to the PTY via `conductorWrite:` -> `writeTaskNoBroadcast:` -> `writeTaskImpl:`, writing directly to the local shell's stdin.

3. All conductor commands are base64-encoded (`Conductor.swift:2587`) and chunked at 128 characters before writing to the PTY.

4. The attacker crafts sshargs so that `base64("run " + padding + magic_bytes)` produces a last chunk equal to `ace/c+aliFIo` - a valid relative path, valid base64-of-UTF-8, and a planted executable.

5. Conductor protocol responses are faked via OSC 135 sequences in the same file, walking the state machine through `getshell` -> `pythonversion` (fail) -> `execLoginShell` -> `run(commandArgs)`.

6. The shell receives `ace/c+aliFIo` as stdin input and executes it as a relative path.

### Affected code paths

| Step | File | Line | Issue |
|------|------|------|-------|
| DCS 2000p hook | `VT100DCSParser.m` | 527 | No `terminalIsTrusted` check |
| Conductor created | `PTYSession.m` | 17760 | Attacker-controlled `sshargs` |
| Commands to PTY | `Conductor.swift` | 2610 | `write(encode(pending))` -> shell stdin |
| Shell execution | `PTYSession.m` | 22650 | `conductorWriteString:` -> `writeTaskNoBroadcast:` |

## PoC

**Generate:**

```sh
python3 genpoc.py
```

Creates `poc.zip` containing:
- `ace/c+aliFIo` - executable shell script that runs `cat /etc/passwd`
- `readme.txt` - trigger file with embedded escape sequences

**Exploit (in iTerm2):**

```sh
unzip poc.zip
cat readme.txt
```

The contents of `/etc/passwd` will be printed, demonstrating arbitrary command execution.

## Impact

- **Severity:** High
- **Attack vector:** Local file (`cat`), curl response, SSH MOTD, or any terminal output
- **User interaction:** Victim must display the malicious content in iTerm2
- **Authentication required:** None
- **Privileges gained:** Code execution as the user running iTerm2

The attack works with default iTerm2 settings - DCS 2000p bypasses the `terminalIsTrusted` / `disablePotentiallyInsecureEscapeSequences` gate entirely.

## Credit
Once confirmed, please use following credit for CVE request:
Hung Nguyen (mov) from Calif.io
