# Apache/mod_php Docker lab

This lab builds a WordPress 7.0.1 site on PHP 8.1.34 running under
`apache2handler` instead of PHP-FPM. It is intended for local reproduction of
the wp2shell chain in this directory.

Start it from `wp2root/`:

```console
./docker/setup.sh
```

The script builds the image, starts MariaDB and Apache, installs WordPress, and
prints the runtime details. The site is exposed at:

```text
http://localhost:8083/
```

Default dashboard credentials:

```text
admin / SuperSecret123!
```

The image enables the restricted PHP profile used by the post-exploitation
tests:

```text
disable_functions = system,passthru,exec,shell_exec,proc_open,popen,pcntl_exec
```

A quick core-chain check is:

```console
python3 wp2shell.py http://localhost:8083 --stop-after-admin --wait 120
```

The full `wp2shell.py` driver also exposes the restricted-runtime UAF modes.
For example:

```console
python3 wp2shell.py http://localhost:8083 --uaf-exec 'id; uname -a' --wait 120
```

`wp2shell_uaf.py` is only a smaller wrapper around those same `--uaf-*`
actions; it is not required for `--uaf-exec`.

To remove the lab and its database/content volumes:

```console
docker compose -f docker-compose.yml down -v
```
