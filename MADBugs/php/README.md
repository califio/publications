# MAD Bugs: Finding and Exploiting a 20-Year-Old Unserialize Use-After-Free in PHP

A use-after-free in PHP's `unserialize()` `var_hash` machinery, exploited locally and remotely. The vulnerable code path has been present since PHP 5.1.

| File | What |
|---|---|
| [`blog.md`](blog.md) | Blog post (written by humans) |
| [`WRITEUP.md`](WRITEUP.md) | Technical write-up: local and remote exploitation |
| [`local_exploit.php`](local_exploit.php) | Local PoC: `disable_functions` bypass on PHP 8.5.5 |
| [`run_poc.sh`](run_poc.sh) | Runs `local_exploit.php` in `php:8.5-cli` via Docker (or builds PHP 8.5.5 from source with `run`) |
| [`remote_app.php`](remote_app.php) | Vulnerable HTTP endpoint (`CachedData::unserialize` is one statement) |
| [`php8_remote.py`](php8_remote.py) | Remote exploit driver against `remote_app.php` |
| [`php8_remote_original.py`](php8_remote_original.py) | The original (unedited) AI-generated remote exploit; `php8_remote.py` is the cleaned-up version |
| [`Dockerfile`](Dockerfile) | `php:8.5-apache` + the vulnerable endpoint |
| [`run_remote_poc.sh`](run_remote_poc.sh) | Builds the Docker image and runs the remote chain |

The audit skill that found this bug, `/php-unserialize-audit`, is published at [github.com/califio/skills](https://github.com/califio/skills).

## A note on the artifacts

The write-ups and PoCs in this series are AI-generated and human-verified. We keep human editing to a minimum so the artifacts document the current state of the art, which means we don't edit out hallucinations or slop. We do verify that the PoCs work. The blog posts are written by humans.
