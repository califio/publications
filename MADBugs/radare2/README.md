# MAD Bugs: Discovering a 0-Day in Zero Day

Here’s how I used Claude to find and patch a radare2 0-day on my first day at Calif.

**Timeline:**

All times are in GMT+8 on 2026-04-06.

- **09:00 AM:** First day at Calif
- **10:18 AM:** Installed Claude Code
- **11:24 AM:** Discovered vulnerability
- **11:48 AM:** Generated RCE PoC 
- **2:48 PM:**  [Reported](https://github.com/radareorg/radare2/issues/25730) vulnerability
- **3:47 PM:** Opened [Fix PR](https://github.com/radareorg/radare2/pull/25731)
- **5:00 PM:** Merged PR

## The Target: radare2

[radare2](https://github.com/radareorg/radare2) (r2) is an open-source, CLI-based reverse engineering framework.

I decided to focus on reverse engineering tools for two reasons:

1. I actually use them. I even built an [r2-based CTF challenge](https://jro.sg/CTFs/TISC%202024%20-%20Imphash/) back in 2024.
2. Parsing and analyzing dozens of executable formats is hard. Historically, binary file parsing has been a rich source of bugs.

An unexpected bonus was the radare2 team's very public disclosure policy: security bugs are reported directly on GitHub Issues, just like any other bug. Combined with their rapid triage and patch turnaround, this made for one of the shortest bug-to-patch cycles I've ever experienced.

## Vulnerability Discovery: Prompt Commentary

Setup was simple: a fresh clone of radare2 from GitHub, and Claude Code running with `--dangerously-skip-permissions`. The model was Claude Opus 4.6 (1M context) with high effort.

Below, I'll walk through the prompts I used, explain the reasoning behind each one, and describe how Claude responded.

> **Me:** Users are reporting that they have experienced unplanned code execution when analyzing untrusted binaries with this project. Figure out how this has happened.

Previous [MAD Bugs](https://blog.calif.io/p/mad-bugs-vim-vs-emacs-vs-claude) posts had success with an incident-response-style prompt, so I went with something similar here.

Claude came back with 5 bugs. They looked plausible, but all of them required non-standard configurations or explicit user approval. I followed up to narrow the scope:

> **Me:** The users are using default configuration with no projects. They did not perform any suspicious actions either. Assess for memory corruption bugs or other more complex vectors

This time, Claude reported 7 "Confirmed Exploitable Vectors," including 3 "Critical" heap and integer overflows. Naturally, I was skeptical, so I asked it to:

> **Me:** Develop a poc for the unpatched vulnerabilities. Determine if an attacker could have bypassed the patches for the known bugs

The second sentence referenced some recently patched N-days it had found in the Git history, which had been fixed by applying the `r_str_sanitize` function to sanitize untrusted input.

Claude struggled to prove, let alone exploit, the memory corruption vulnerabilities. It did appear to be making progress on a "heap leak" issue, though, so I gave it a nudge:

> **Me:** What if you built radare with asan to help with the exploit debugging 

> **Me:** Assess the exploitability of the vulnerabilities. The attacker must be able to achieve full code execution just by the user loading a binary for analysis  

Unfortunately, ASAN revealed that the "heap leak" was just a memory leak, not any kind of information disclosure bug:

```
==44349==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 48 byte(s) in 1 object(s) allocated from:
```

Time to reset expectations and point Claude toward a more promising direction:

> **Me:** Memory leak is not a vulnerability. Show a vulnerability with real impact, such as heap overflow. Also, dig deeper into r_str_sanitize and where it should be used but is missing. Explain the impact of those vulns    

Claude tried hard to exploit various stack and heap buffer overflows, but failed to trigger a single ASAN crash. It had, however, developed a solid understanding of the command injection N-days, so I redirected:

> **Me:** Focus on command injection. Find another vulnerability.

Watching Claude's thoughts stream rapidly across my screen didn't inspire much confidence. 

It seemed like we were running out of leads. Then this appeared:

```
Let me now look for the ONE remaining angle: the RAD-mode output that gets executed via . (dot) commands. Let me look for ".i" patterns in automatic loading:
```

Soon, we went from "it's over" to "we are so back":

```
Confirmed: line 1458 is the only RAD-mode cb_printf with an unsanitized binary-derived string. The vulnerability is clear:

...

Impact: Full code execution when a user opens a PE binary that has a crafted PDB file in the PDB search path. Default configuration, no user interaction beyond r2 binary.exe.

Fix: Sanitize name before interpolation at line 1458, using r_name_filter_dup() or r_str_sanitize().
```

This looked very plausible. I asked Claude to:

> **Me:** Generate a test .exe and .pdb file. Prove that the vulnerability is real and exploitable

To do this, Claude had to construct a valid [PDB file](https://en.wikipedia.org/wiki/Program_database) containing a malicious symbol name. PDB is a relatively complex binary format, so this took some time.

At this point, I was fairly confident we were in the home stretch. I offered one last hint:

> **Me:** Can you use any libraries to build the pdb? Maybe that will be easier 

But Claude didn't need it. Shortly after, we had the proof:

```
Arbitrary shell command execution confirmed. A crafted debug.pdb file alongside a PE binary causes !echo PWNED>/tmp/r2_poc_output to execute when the user runs idp in radare2. The output file /tmp/r2_poc_output contains PWNED.
```

One final prompt to wrap things up:

> **Me:** Great job! Now, generate a report for this vulnerability. Also create a poc.py, which takes --cmd and generates the target.exe and .pdb file that executes the given command       

Total context used was 352.4k/1M tokens.

## Vulnerability Analysis

PDB files contain symbols: mappings between function names and their addresses. Knowing where functions live is incredibly helpful for malware analysis, so r2 has several commands that parse and display this information.

There's the [`idpi`](https://github.com/radareorg/radare2/blob/25edd02/libr/bin/format/pdb/pdb.c#L1463) command, which prints the symbols available:
```
[0x140001000]> idpi
0x140001000  0  .text  my_cool_function
```

And there's `idpi*`, which prints the r2 commands needed to convert symbol information into flags — essentially labels for addresses in r2.

```
[0x140001000]> idpi*
f pdb.my_cool_function = 0x140001000 # 0 .text
"fN pdb.my_cool_function my_cool_function"
```

The `f` command creates a flag (an offset-name mapping) at an address, and `fN` sets its "real name" — the original, unsanitized display name stored separately from the flag's identifier.

Finally, there's [`idp`](https://github.com/radareorg/radare2/blob/25edd02/libr/core/cmd_info.inc.c#L1886), which is actually an alias for `.idpi*`. The dot prefix means "run this command, then execute the output". 

You can probably see where this is going, so let's just jump right into the [implementation](https://github.com/radareorg/radare2/blob/25edd02/libr/bin/format/pdb/pdb.c#L1452-L1458) of the `idpi*` command:

```c
// pdb.c:1451 – filtered_name is sanitized via r_name_filter_dup()
filtered_name = r_name_filter_dup (r_str_trim_head_ro (name));
// pdb.c:1452 – safe: filtered_name in flag creation
pdb->cb_printf ("f pdb.%s = 0x%" PFMT64x " # %d %.*s\n", filtered_name, ...);
// pdb.c:1458 – VULNERABLE: raw `name` from PDB binary data, NOT sanitized
pdb->cb_printf ("\"fN pdb.%s %s\"\n", filtered_name, name);
```

By crafting a PDB with a function name like `x" ;!open -a Calculator #"`, we can break out of the double-quoted command and inject arbitrary r2 commands. Since r2 supports executing system commands, RCE follows trivially.

```
[0x140001000]> idpi*
f pdb.x____open__a_Calculator_ = 0x140001000 # 0 .text
"fN pdb.x____open__a_Calculator_ x" ;!open -a Calculator #"
```

## PoC

Video: http://youtube.com/watch?v=mmc7A__J_hY

Code: [poc.py](poc.py)

## Patch Development: Prompt Commentary

In a fresh Claude Code session, I started off with:

> **Me:** Read the poc and report. Determine when the bug was introduced and produce a patch commit, along with tests that prevent a regression of this bug

The first patch Claude generated fixed the vulnerability, but it broke functionality as well:
```diff
-	pdb->cb_printf ("\"fN pdb.%s %s\"\n", filtered_name, name);
+	char *safe_name = r_name_filter_dup (name);
+	pdb->cb_printf ("\"fN pdb.%s %s\"\n", filtered_name, safe_name);
+	free (safe_name);
```

With that patch applied, the output of `idpi*` would be:
```
[0x140001000]> idpi*
f pdb.x____open__a_Calculator_ = 0x140001000 # 0 .text
"fN pdb.x____open__a_Calculator_ x____open__a_Calculator_"
```

However, this also strips special characters from legitimate function names, such as `std::ostream::operator<<(std::ostream& (*)(std::ostream&))`:

```
[0x140001440]> idpi*
f pdb.std::ostream::operator___std::ostream____std::ostream__ = 0x1400014c0 # 0 .text
"fN pdb.std::ostream::operator___std::ostream____std::ostream__ std::ostream::operator___std::ostream____std::ostream__"
```

Thus, I got Claude to reconsider:

> **Me:** What is the intent of the fN command and does the fix affect its intend       behavior? 

> **Me:** This is a critical problem. if we sanitize the real name, then this is useless. How can we properly address it?  

Claude came back with a clean solution: base64-encode the raw name before interpolation.

```
Here's what I found. There are two viable approaches:

Option 1: Add base64: support to fN (matches existing pattern)

The flag system already uses base64 in several places:
- fC (flag comment) accepts base64: prefix and decodes it at
cmd_flag.inc.c:2085
- fu serializes realname as base64 at line 1536, and decodes it back at line
1517

But fN itself (line 2163) does not support the base64: prefix — it takes the
raw string directly via strchr(name, ' ') and passes it straight to
r_flag_item_set_realname.

The fix would be two-sided:

1. Emit side (print_gvars): base64-encode the raw name
2. Receive side (fN handler): detect and decode base64: prefix

This is the cleanest approach because it completely avoids the parsing problem
— base64 output contains only [A-Za-z0-9+/=], which has zero overlap with r2
metacharacters.
```

Satisfied with the approach, I opened a [PR with Claude's changes](https://github.com/radareorg/radare2/pull/25731) and waited for the maintainers to respond.

## Resolution

About an hour later, a maintainer pointed out that the vulnerability could be fixed more simply — by prefixing the `fN` command with a single quote (`'`), which disables special character processing in r2.

```
# Safe - no calc popped
'fN pdb.x____open__a_Calculator_ x;!open -a Calculator # 
```

Nonetheless, they recognized it as a real and critical vulnerability, and agreed that the base64 prefix was a worthwhile addition.

The PR was [merged](https://github.com/radareorg/radare2/commit/0e38152560e689327a74d2944fa45ba7afd4cb33), and string sanitization was [further enhanced](https://github.com/radareorg/radare2/commit/253587680e000266e94cbf98c27a17ada4cd29e9) in a follow-up commit — likely part of a broader effort to address the spate of recent command injection vulnerabilities.

## Conclusion

We are now in an era where AI can rapidly discover and exploit bugs in large, complex open-source projects. Constructing a valid PDB file would have taken me at least a few hours manually. Claude did it in under 30 minutes.

That said, finding bugs is the easy part. Claude just needs to identify a possible injection site, trace how to reach it, and develop a PoC it can verify and iterate on.

Patching is harder. It requires a much deeper understanding of the project, not just where the vulnerability occurs, but why the surrounding code is designed the way it is. In this case, Claude's first patch was technically correct but semantically wrong: it fixed the injection without understanding what `fN` was actually for. It took explicit pushback to get to a solution that was both safe and useful.

That dynamic is worth keeping in mind. AI-assisted vulnerability research compresses the timeline dramatically, but the human still has to understand the system well enough to know when a fix is incomplete. The bottleneck has shifted, from finding bugs to understanding them well enough to fix them properly.
