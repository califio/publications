# An AI audit of FreeBSD

*15 kernel bugs, including 3 RCEs, 5 LPEs, and 1 bhyve escape.*

Since we started this campaign of [hacking the Internet with AI](https://blog.calif.io/t/madbugs), we've learned something many of you already knew: the Internet runs on volunteers. Projects that are critical to Internet security and culture are staffed by tiny groups of people, sometimes one person. OpenSSH, which protects almost every remote shell on the Internet, is maintained by a small team led by a single Aussie (Hi Damien!).

We feel like we owe these maintainers something. Without the Internet, and the open source software that runs it, we would not have learned what we learned, made the friends we made, or had the careers we have today. So we decided to pair our experts and our AI with open source projects that could use the help. FreeBSD is where we started.

At the end of March we published [the first AI-assisted FreeBSD remote kernel exploit](https://github.com/califio/publications/tree/main/MADBugs/CVE-2026-4747). Earlier this month we reported [a CVE in exeCVE](https://github.com/califio/publications/tree/main/MADBugs/freebsd-CVE-2026-7270). We also reported 3 RCEs in a rarely used module. Seeing the team stretched thin, we thought we should try to help more than just adding to the pile, and reached out to them. The team told us what to focus on, and we let the AI go brr.

Within the first few weeks of that work, the audit surfaced more bugs:

- **5 local privilege escalations**
- **1 bhyve guest-to-host escape**
- **a handful of memory disclosures and DoS**

In total, we have reported 15 bugs. All in the kernel. We have also shared the audit skill we used to find some of them with the team.

This post is about how we got there.

## What we want to achieve

When we sat down with the FreeBSD team, we agreed on two things:

1. Make finding bugs in FreeBSD more expensive.
2. Help the FreeBSD team find, eliminate and prevent more bugs after we are no longer around.

We are not trying to chase CVE numbers or post bug counts. We just want to be useful to the people running the project.

## How we work

Maintainers of widely-used open source projects like FreeBSD are drowning in reports, and their attention is the most expensive resource in this whole enterprise. The first rule of being useful is to not waste it. A few things we have converged on:

**Send only high or critical bugs.** We focus our outbound reports on what we believe are high or critical vulnerabilities. Sometimes a bug we think is high gets downgraded by the maintainers on closer inspection, and we largely follow their own scoring rather than arguing.

**Keep reports short.** Everyone likes a short report. A one-liner and a PoC is much better than fifteen pages of meandering analysis. The deep dive can go in a follow-up if anyone asks for it.

**Suggest patches, but do not insist on them.** Some maintainers love receiving suggested patches; some prefer to write the fix themselves. We default to including a patch in the report, clearly labeled as a suggestion, so the maintainer can take it, modify it, or ignore it without any back-and-forth.

**Spend time with people.** Email and tracker tickets are necessary, but a single video call early on does more for the working relationship than any number of careful issue templates. After our first meeting with the FreeBSD team, we set up a direct channel with them, and many of the bugs we have reported since then have gone from report to fix in days.

FreeBSD is the first such collaboration we are writing about publicly, but it is not the only one. Similar work is already underway with other projects that keep the Internet running, and we plan to share more as those efforts mature.

## Warez

A MAD Bugs post must include some warez drops, so today we are publishing exploits and writeups for three of the LPEs:

- **[setcred (CVE-2026-45250)](https://github.com/califio/publications/tree/main/MADBugs/freebsd/setcred-CVE-2026-45250)**: a one-character `sizeof` confusion in `kern_setcred_copyin_supp_groups` turns into a stack overflow in `user_setcred`'s frame and then a local root shell. Only FreeBSD 14.4 is exploitable, despite the same source bug being present in 14.3 and 15.0.

[setcred demo](nocred.gif)

- **[ptrace (CVE-2026-45253)](https://github.com/califio/publications/tree/main/MADBugs/freebsd/ptrace-CVE-2026-45253)**: `ptrace(PT_SC_REMOTE)` skips a bounds check on the redirected syscall number, giving out-of-bounds indexing into the sysent table that we chain into LPE.

[ptrace demo](ptrace.gif)

- **[procdesc (CVE-2026-45251)](https://github.com/califio/publications/tree/main/MADBugs/freebsd/file-CVE-2026-45251)**: `procdesc_free()` frees a `struct procdesc` with an embedded `pd_selinfo` without draining poll waiters. We reclaim the slot with `SCM_RIGHTS` filedescents, fire two stale `TAILQ_REMOVE`s, and get arbitrary kernel-pointer writes.

[procdesc demo](procdesc.gif)

The exploits and the writeups were written by AI. We have decided to keep the AI text as-is, as a historical artifact showing what AI vulnerability research looked like in 2026. The exploits, on the other hand, are all verified by us, and they work. By publishing them, we hope more people can learn from these techniques and bring more help to FreeBSD. The remaining bugs from the audit will be released as the FreeBSD team ships the fixes.

For curious readers, the [repository](https://github.com/califio/publications/tree/main/MADBugs/freebsd) also contains a few bonus exploits, mostly cooked by the AI from public FreeBSD advisories that shipped without working PoCs.

## Thanks

To the FreeBSD team, for working with us and for taking the work seriously. To OpenAI and Anthropic, for the tokens. And to all maintainers who keep the Internet running with very little credit and very few hands: thank you.
