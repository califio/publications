# An AI audit of FreeBSD

Companion repo for the blog post [An AI audit of FreeBSD](blog.md).

## Featured exploits

The three LPEs discussed in the post:

- [setcred (CVE-2026-45250)](setcred-CVE-2026-45250) — one-character `sizeof` confusion in `kern_setcred_copyin_supp_groups`. Only FreeBSD 14.4 is exploitable, despite the same source bug being present in 14.3 and 15.0.
- [ptrace (CVE-2026-45253)](ptrace-CVE-2026-45253) — `ptrace(PT_SC_REMOTE)` skips a bounds check on the redirected syscall number, giving out-of-bounds indexing into the sysent table.
- [procdesc (CVE-2026-45251)](file-CVE-2026-45251) — `procdesc_free()` releases an embedded `pd_selinfo` without draining poll waiters, turned into an arbitrary kernel-pointer write via `SCM_RIGHTS` reclaim.

## Bonus

The repository also includes a few exploits that did not make it into the post, kept here for curious readers. Most were cooked by AI from public FreeBSD security advisories that shipped without working proof-of-concept code:

- [pmap_pkru (CVE-2026-6386)](amd64-CVE-2026-6386) — a 1 GB user superpage walked as a page directory by `pmap_pkru_update_range()`, used to corrupt `/usr/bin/su`'s PLT in the buffer cache. From [FreeBSD-SA-26:11.amd64](https://www.freebsd.org/security/advisories/FreeBSD-SA-26:11.amd64.asc).
- [dhclient (CVE-2026-42511)](dhclient-CVE-2026-42511) — a rogue DHCP server injecting newlines into the lease file's `medium` directive, bypassing the command-substitution filter and getting code execution as root. From [FreeBSD-SA-26:12.dhclient](https://www.freebsd.org/security/advisories/FreeBSD-SA-26:12.dhclient.asc).
- [tty (CVE-2026-5398)](tty-CVE-2026-5398) — a `TIOCNOTTY` UAF of `struct session` on arm64, reclaimed via `cap_ioctls_limit` and chained into a fake-root-credential write. From [FreeBSD-SA-26:10.tty](https://www.freebsd.org/security/advisories/FreeBSD-SA-26:10.tty.asc).

## Notes on the artifacts

The write-ups in this directory are AI-generated and kept as-is, as a historical artifact of what AI vulnerability research looked like in 2026. The exploits are verified by us. They work.
