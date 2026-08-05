# WP2Shell: from REST request confusion to pre-authentication RCE

## Scope and result

This document explains the complete WordPress core chain implemented in
[wp2shell.py](./wp2shell.py). The chain was reproduced against the local
WordPress 7.0.1 PHP-FPM lab and the packaged Apache/mod_php Docker lab, and ends
with a newly created administrator followed by ordinary core plugin upload and
PHP/OS command execution.

The most important point is that this is **not “SQL injection, dump a password
hash, crack it, and log in.”** The injection has two distinct uses:

1. Small synthetic rows turn arbitrary SQL scalar expressions into values in a
   normal REST posts response. These probes discover the live schema, table
   prefix, administrator ID, and six post IDs.
2. A larger UNION returns six complete, attacker-designed rows using those real
   post IDs. WordPress converts the rows into <code>WP_Post</code> objects and
   primes its in-process object cache with them. Core update logic subsequently
   consumes those forged objects, materializes selected fields, publishes a
   forged Customizer changeset, temporarily assumes an administrator identity,
   and re-enters the original REST request as that administrator.

The SQL injection is therefore best understood as an **object factory and
in-request cache-programming primitive**. It is a SELECT-only operation in this
chain. The consequential database writes are performed later by trusted
WordPress code acting on the forged objects.

The public disclosure lists WordPress 6.9.0–6.9.4 and 7.0.0–7.0.1 as affected,
with fixes in 6.9.5 and 7.0.2. WordPress 6.8.5 and earlier are listed as
unaffected by the complete pre-authentication RCE. That classification is
consistent with the tagged source once the SQL sink and the REST reachability
bug are dated separately. See the
[Searchlight Cyber advisory](https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/).

> Lab note: this write-up describes an exploit that creates persistent database
> rows, a privileged user, and an uploaded PHP endpoint. Test only on systems
> where that activity is authorized.

## Executive summary

The attack is one physical anonymous HTTP request to
<code>/batch/v1</code>, but the request contains an outer and an inner batch.
One malformed subrequest causes WordPress to build parallel arrays of different
lengths. During dispatch, a request object validated against route A is paired
with the callback and permission handler selected for route B.

The outer shift lets a widget-shaped request invoke the batch callback. This
bypasses the batch schema's prohibition on inner GET requests. The inner shift
then lets a request validated as a widget invoke the posts collection callback.
The widget schema does not type-check the attacker's unknown
<code>author_exclude</code> query parameter, while the posts callback maps that
raw scalar to <code>WP_Query::author__not_in</code>.

The vulnerable <code>WP_Query</code> code sanitizes
<code>author__not_in</code> only when it is already an array. A scalar string is
cast to a one-element array only after the sanitization branch, joined, and
interpolated into:

    AND wp_posts.post_author NOT IN (<attacker scalar>)

The payload closes the <code>NOT IN</code> expression, makes the legitimate
branch false, and UNIONs complete rows in the physical 23-column
<code>wp_posts</code> order. Setting <code>per_page=500</code> prevents the
normal local ID-only split, so the database result really is
<code>wp_posts.*</code>. WordPress then creates and caches the attacker's
objects.

Two forged post-parent cycles drive core's hierarchy-repair code. The first
causes a forged, past-dated Customizer changeset to be written and published.
The changeset contains a <code>nav_menus_created_posts</code> setting attributed
to a real administrator ID. The Customizer temporarily calls
<code>wp_set_current_user(admin_id)</code> while saving it. Publishing the
forged nav object drives the second parent cycle, whose objects have:

    post_status = parse
    post_type   = request

The normal dynamic post-status action is therefore
<code>parse_request</code>. Core has registered <code>rest_api_loaded()</code>
on that action. It starts another top-level REST serve of the original
<code>/batch/v1</code> request while the in-memory current user is still the
administrator. The shifted users handler now accepts the generated credentials
and creates the new administrator.

With ordinary stock file-modification permissions, that account can upload a
plugin containing a directly requestable PHP endpoint. That final authenticated
administration step turns the core pre-auth primitive into PHP evaluation and
OS command execution.

## The chain at a glance

~~~mermaid
flowchart TD
    A[Anonymous POST to /batch/v1] --> B[Outer malformed-path index shift]
    B --> C[Widget request object invokes batch handler]
    C --> D[Inner GET survives because inner body skipped batch-schema validation]
    D --> E[Inner malformed-path index shift]
    E --> F[Widget-validated request invokes posts handler]
    F --> G[Raw scalar author_exclude maps to author__not_in]
    G --> H[UNION returns full 23-column synthetic post rows]
    H --> I[WP_Query primes forged WP_Post objects into request-local cache]
    I --> J[oEmbed refresh updates a real ID using forged cached fields]
    J --> K[First parent-cycle repair publishes forged Customizer changeset]
    K --> L[Customizer temporarily sets current user to real admin ID]
    L --> M[Second parent-cycle repair fires parse_request]
    M --> N[rest_api_loaded re-enters original /batch/v1 body]
    N --> O[Confused users handler creates generated administrator]
    O --> P[Normal admin plugin upload]
    P --> Q[Direct PHP eval endpoint]
    Q --> R[OS command execution]
~~~

An ASCII rendering of the security-boundary crossings is:

    untrusted JSON
        |
        v
    request object validated as WIDGET
        |
        |  handler index shifted by one
        v
    dispatched as POSTS --> raw scalar reaches SQL construction
        |
        v
    SELECT rows interpreted as trusted WP_Post objects
        |
        v
    trusted update/hierarchy/Customizer code performs writes
        |
        v
    temporary in-memory ADMIN context
        |
        |  top-level REST server re-entered
        v
    anonymous request body processed with admin capabilities

## Version history: four separate questions

It is easy to get the timeline wrong by asking only “when did
<code>author__not_in</code> exist?” Four events matter:

| Version | Source behavior | Security meaning |
|---|---|---|
| 3.6 and earlier | No <code>author__not_in</code> query variable | This exact sink does not exist. |
| 3.7 through 6.7 | The value is cast to an array and every element passes through <code>absint()</code> before interpolation | A UNION-shaped scalar becomes an integer, normally zero. The parameter exists, but this SQL injection does not. |
| 6.8 through 6.8.5 | Sanitization is conditional on <code>is_array()</code>; a scalar is interpolated unsanitized | A latent scalar SQL-injection sink now exists. Normal posts REST validation still supplies an integer array. |
| 6.8.5 | A malformed batch path becomes <code>WP_Error</code>, but route matching still tries to call request methods on that error | The malformed path aborts/fails; it does not create a useful compacted match array. The complete disclosed stock chain is not reachable. |
| 6.9.0 through 6.9.4 | New error-skip branches omit a matching <code>$matches[]</code> element, while later dispatch continues to index arrays in parallel | The REST request/handler confusion makes the 6.8 scalar sink anonymously reachable. This is the beginning of the complete disclosed chain. |
| 7.0.0 through 7.0.1 | Same relevant behavior | Affected. |
| 6.9.5 and 7.0.2 | Integer-list parsing, match-array alignment, and REST re-entry guards | Fixed at three independent links. |

Many individual gadgets are much older than the vulnerability:

- dynamic post-status hooks date to early WordPress;
- <code>author__not_in</code> was added in 3.7, initially with safe scalar
  handling;
- <code>rest_api_loaded()</code> and the REST server appeared in 4.4;
- REST posts plus the relevant Customizer changeset/nav-created-post behavior
  appeared in the 4.7 era;
- batch v1 appeared in 5.6;
- the widgets REST controller appeared in 5.8 and became batch-enabled in 5.9;
  and
- <code>WP_REST_Server::is_dispatching()</code> existed by 6.5, but was not
  used to reject nested top-level serving until the security fix.

Old gadgets do not imply an old exploit. The earliest disclosed stock chain is
where the unsafe 6.8 SQL scalar handling and the new 6.9 match-array compaction
coexist.

### Why WordPress 3.7.1 is not vulnerable

The exact 3.7.1 source is:

~~~php
if ( ! empty( $q['author__not_in'] ) ) {
    $author__not_in = implode(
        ',',
        array_map( 'absint', array_unique( (array) $q['author__not_in'] ) )
    );
    $where .= " AND {$wpdb->posts}.post_author NOT IN ($author__not_in) ";
}
~~~

For a scalar such as:

    0) AND 1=0 UNION ALL SELECT ...

the cast produces a one-element array and <code>absint()</code> converts that
element to <code>0</code>. SQL punctuation never reaches the query. This is
visible in the official
[WordPress 3.7.1 query source](https://core.svn.wordpress.org/tags/3.7.1/wp-includes/query.php).

### The SQL regression appears in 6.8

The 6.7-to-6.8 change replaced unconditional element sanitization with:

~~~php
if ( ! empty( $q['author__not_in'] ) ) {
    if ( is_array( $q['author__not_in'] ) ) {
        $q['author__not_in'] = array_unique(
            array_map( 'absint', $q['author__not_in'] )
        );
        sort( $q['author__not_in'] );
    }
    $author__not_in = implode( ',', (array) $q['author__not_in'] );
    $where .= " AND {$wpdb->posts}.post_author NOT IN ($author__not_in) ";
}
~~~

An array remains safe, but a scalar skips <code>array_map('absint', ...)</code>
and survives until interpolation. The adjacent changes sort several query
arrays for stable query/cache behavior; it is reasonable to infer that
normalizing arrays was the refactor's goal, but the security-relevant source
fact is simply that scalar sanitization was lost. Compare the official
[6.7 source](https://core.svn.wordpress.org/tags/6.7/wp-includes/class-wp-query.php)
and
[6.8 source](https://core.svn.wordpress.org/tags/6.8/wp-includes/class-wp-query.php).

The sink alone does not establish the disclosed pre-authentication exploit.
The normal posts REST schema declares <code>author_exclude</code> as an array of
integers, so normal dispatch keeps taking the safe array branch.

### The exploitable desynchronization appears in 6.9

In 6.8.5, malformed paths were already represented as
<code>WP_Error</code>. However, the match-building loop did not skip them; it
fed the error into <code>match_request_to_handler()</code>, which expects a
<code>WP_REST_Request</code> and calls methods such as
<code>get_method()</code>. That path fails instead of shifting the remaining
matches.

WordPress 6.9 added graceful error handling in two places:

~~~php
foreach ( $requests as $single_request ) {
    if ( is_wp_error( $single_request ) ) {
        $has_error    = true;
        $validation[] = $single_request;
        continue;
    }

    $match     = $this->match_request_to_handler( $single_request );
    $matches[] = $match;
    // ...
}
~~~

and:

~~~php
foreach ( $requests as $i => $single_request ) {
    if ( is_wp_error( $single_request ) ) {
        // Emit the error response.
        continue;
    }

    $match = $matches[ $i ];
    // ...
}
~~~

The first <code>continue</code> appends to <code>$validation</code> but not
<code>$matches</code>. The second loop nevertheless indexes
<code>$matches</code> with the original request index. This turns graceful
error handling into a one-position type/handler confusion. The relevant tagged
source is the official
[WordPress 6.9 REST server](https://core.svn.wordpress.org/tags/6.9/wp-includes/rest-api/class-wp-rest-server.php).

## 1. The REST batch desynchronization

### The intended invariant

<code>serve_batch_request_v1()</code> creates three logically parallel arrays:

| Array | Intended element at index <code>i</code> |
|---|---|
| <code>$requests[i]</code> | Parsed request object for subrequest <code>i</code> |
| <code>$matches[i]</code> | Route and handler matched for that same request |
| <code>$validation[i]</code> | Validation/sanitization result for that same request |

Correct dispatch requires:

    count($requests) === count($matches) === count($validation)

and, more importantly, semantic identity:

    matches[i] belongs to requests[i]

### What the malformed path does

The path <code>:</code> makes <code>wp_parse_url()</code> return false. Core
appends a <code>parse_path_failed</code> error to
<code>$requests</code>. During the 6.9/7.0.1 match pass it appends the same error
to <code>$validation</code>, then continues without adding an element to
<code>$matches</code>.

For three subrequests, the arrays become:

| Index | <code>$requests</code> | <code>$validation</code> | Compact <code>$matches</code> |
|---:|---|---|---|
| 0 | malformed-path error | malformed-path error | match for original request 1 |
| 1 | carrier request A | validation for carrier A | match for original request 2 |
| 2 | target request B | validation for target B | no element |

At dispatch index 1, WordPress combines:

    request object: requests[1]      (carrier A)
    validation:     validation[1]    (carrier A's schema)
    route/handler:  matches[1]       (target B's handler)

The carrier is therefore validated and sanitized using A's definition, but its
permission callback and application callback come from B. This is not HTTP
request smuggling between a proxy and origin server; “desync” here means an
**in-process index desynchronization among parallel PHP arrays**.

### Outer desync: reach the batch handler with an unvalidated nested body

The registered batch schema permits only POST, PUT, PATCH, and DELETE for its
inner requests; GET is not in the enum. The exploit needs a GET posts handler,
so a directly submitted inner batch would fail schema validation.

The outer batch is conceptually:

| Original index | Request | Match compacted to | Dispatch consequence |
|---:|---|---:|---|
| 0 | <code>POST :</code> | none | Error response |
| 1 | <code>POST /wp/v2/widgets</code>, body contains nested <code>requests</code> | 0 | Its request object passes widget validation |
| 2 | <code>POST /batch/v1</code> | 1 | Its batch handler is invoked at dispatch index 1 |

So the object at request index 1 has:

    route/method/body shape validated as: POST /wp/v2/widgets
    callback actually invoked:             serve_batch_request_v1

The widget route does not define or recursively validate a
<code>requests</code> member in this body. The batch callback subsequently
reads that member as its own nested request list. The nested list therefore
never passed the real batch route's method enum, and it may contain GET.

A minimal schematic physical body is:

~~~json
{
  "requests": [
    {
      "method": "POST",
      "path": ":"
    },
    {
      "method": "POST",
      "path": "/wp/v2/widgets",
      "body": {
        "sidebar": "wp_inactive_widgets",
        "requests": [
          {
            "method": "POST",
            "path": ":"
          },
          {
            "method": "POST",
            "path": "/wp/v2/widgets?per_page=500&orderby=none&author_exclude=<SQL>",
            "body": {
              "sidebar": "wp_inactive_widgets"
            }
          },
          {
            "method": "GET",
            "path": "/wp/v2/posts"
          }
        ]
      }
    },
    {
      "method": "POST",
      "path": "/batch/v1"
    }
  ]
}
~~~

The outer handler consumes <code>body.requests</code> from the widget request.
That is why the inner GET can exist even though the registered batch schema
would reject the same JSON if it had validated it directly.

### Inner desync: give raw widget parameters to the posts handler

The minimal inner SQL probe is:

| Original index | Request object | Compact match |
|---:|---|---|
| 0 | <code>POST :</code> | widget collection |
| 1 | widget carrier with scalar <code>author_exclude</code> | posts GET collection |
| 2 | <code>GET /wp/v2/posts</code> | none |

At index 1 the posts collection handler receives the widget request object.
This is the exact bridge from the REST bug to the SQL sink.

## 2. How the confused request reaches SQL

### Normal path: safe typed array

The posts collection declares:

~~~php
$query_params['author_exclude'] = array(
    'type'  => 'array',
    'items' => array( 'type' => 'integer' ),
);
~~~

It then maps the public REST name to the internal query name:

~~~php
'author_exclude' => 'author__not_in'
~~~

Under normal dispatch, a scalar UNION string is rejected or sanitized before
<code>WP_Query</code>. See the official
[7.0.1 posts controller](https://core.svn.wordpress.org/tags/7.0.1/wp-includes/rest-api/endpoints/class-wp-rest-posts-controller.php).

### Confused path: raw scalar, posts callback

The widget collection schema does not register
<code>author_exclude</code>. Unknown query parameters remain on the
<code>WP_REST_Request</code> but are not validated as a posts integer array.
The carrier encodes the parameter without square brackets:

    author_exclude=0%29+AND+1%3D0+UNION+ALL+SELECT+...

Consequently <code>wp_parse_str()</code> produces a scalar string, not an
array. When the shifted posts callback runs, its mapping code asks the request
for <code>author_exclude</code> and copies that raw scalar into:

    $query_args['author__not_in']

The data flow is:

~~~mermaid
flowchart LR
    A[URL query scalar author_exclude] --> B[wp_parse_str: string]
    B --> C[Validated only as unknown widget parameter]
    C --> D[Shifted WP_REST_Posts_Controller callback]
    D --> E[author_exclude maps to author__not_in]
    E --> F[is_array is false]
    F --> G[No absint element sanitization]
    G --> H[Raw text interpolated inside SQL NOT IN]
~~~

The handler confusion matters twice: it supplies the posts callback that knows
the mapping, while preserving the carrier route's weak validation history.

## 3. What the SQL injection actually does

### Conventional SQL injection versus this chain

| Question | Conventional account-takeover SQLi | This chain |
|---|---|---|
| Primary target data | Password hashes, sessions, API keys, email addresses | A few structural values, then complete synthetic post rows |
| Main objective | Learn a secret or directly change a record | Make WordPress instantiate attacker-designed <code>WP_Post</code> objects |
| Feedback channel | Error output, UNION table, Boolean/timing oracle | Rendered content of a synthetic REST post |
| Important identifier | User credential/session | Real post IDs used as object-cache keys; a non-secret administrator ID used by Customizer |
| Database writes | Often injected directly or performed after login | The injection is SELECT-only; trusted WordPress update code performs later writes |
| End of SQL stage | Data exfiltration | A programmed in-memory object graph ready for core consumers |

The reconnaissance expressions make the exploit portable, but the six-row
poison is the reason SQLi becomes RCE without extracting or cracking a
credential.

### Payload anatomy

The structural form generated by <code>union_payload()</code> is:

    0) AND 1=0
    UNION ALL SELECT <23 expressions>
    [UNION ALL SELECT <23 expressions> ...]
    -- -

Placed into the vulnerable clause, the effective query becomes conceptually:

    SELECT wp_posts.*
      FROM wp_posts
     WHERE ...
       AND wp_posts.post_author NOT IN (0)
       AND 1=0
    UNION ALL
    SELECT <23 attacker-controlled expressions>
    -- - remainder of original query

Each part has a purpose:

| Fragment | Purpose |
|---|---|
| <code>0)</code> | Supplies a legal value and closes the original <code>NOT IN (...)</code>. |
| <code>AND 1=0</code> | Suppresses real posts so only synthetic rows reach WordPress. |
| <code>UNION ALL</code> | Adds attacker-designed rows without duplicate elimination. |
| 23 expressions | Matches the physical <code>wp_posts.*</code> projection and defines every <code>WP_Post</code> field. |
| <code>-- -</code> | Comments out the remainder of the original generated query. |

This does not use <code>INTO OUTFILE</code>, MySQL's <code>FILE</code>
privilege, stacked statements, or an UPDATE/INSERT injected into the query.
The attacker controls SELECT results, and WordPress itself supplies the later
writes.

### Why exactly 23 columns

Stock vulnerable releases select <code>wp_posts.*</code>. MySQL requires every
UNION arm to return the same number of columns, in compatible positions. The
physical core layout is:

| # | Column | Forgery use |
|---:|---|---|
| 1 | ID | Collide with a real seeded row |
| 2 | post_author | Real administrator ID |
| 3 | post_date | Make the future changeset past-dated |
| 4 | post_date_gmt | UTC form used by future-to-publish normalization |
| 5 | post_content | Marker, embed shortcode, or changeset JSON |
| 6 | post_title | Benign diagnostics |
| 7 | post_excerpt | Empty filler |
| 8 | post_status | <code>publish</code>, <code>future</code>, <code>auto-draft</code>, or <code>parse</code> |
| 9 | comment_status | Closed filler |
| 10 | ping_status | Closed filler |
| 11 | post_password | Empty filler |
| 12 | post_name | Preserve oEmbed cache key or provide changeset UUID |
| 13 | to_ping | Empty filler |
| 14 | pinged | Empty filler |
| 15 | post_modified | Old timestamp for cache staleness |
| 16 | post_modified_gmt | Old UTC timestamp for cache staleness |
| 17 | post_content_filtered | Empty filler |
| 18 | post_parent | Construct hierarchy cycles |
| 19 | guid | Empty filler |
| 20 | menu_order | Zero filler |
| 21 | post_type | <code>oembed_cache</code>, <code>customize_changeset</code>, <code>page</code>, or <code>request</code> |
| 22 | post_mime_type | Empty filler |
| 23 | comment_count | Zero filler |

“A plugin-altered table or query projection” means either:

- a plugin has physically changed the posts table's column count/order; or
- a <code>posts_fields</code>, <code>posts_clauses</code>, or related query
  filter changes the SELECT projection from the expected
  <code>wp_posts.*</code>.

The UNION is positional. Either change can yield a column-count error, map an
expression into the wrong object property, or make the query “filtered” so
WordPress primes real rows instead of the returned forged objects. The PoC
therefore performs a marker probe and validates the live
<code>information_schema.COLUMNS</code> order before poisoning.

### Why <code>per_page=500</code> is part of the primitive

For an unfiltered full-post query, <code>WP_Query</code> chooses its split path
when either:

~~~php
wp_using_ext_object_cache()
|| ( ! empty( $limits ) && $query_vars['posts_per_page'] < 500 )
~~~

The split path first selects only <code>wp_posts.ID</code> and then retrieves
real post objects by ID. A 23-column UNION cannot fit a one-column projection,
and even an ID-only injection would not provide attacker-controlled
<code>post_type</code>, <code>post_status</code>, content, dates, or parents.

The carrier supplies <code>per_page=500</code>, exactly crossing the local split
threshold and preserving the complete <code>wp_posts.*</code> result. A normal
posts request caps <code>per_page</code> at 100; because this request was
validated as a widget, that cap was never applied. The carrier also uses
<code>orderby=none</code> to avoid an unnecessary generated ordering over the
UNION result.

An external Redis/Memcached-style object cache makes the first condition true
regardless of 500. The current construction detects that incompatible
projection and stops. This is a failure condition for this PoC, not a
principled patch for the underlying REST confusion or SQL sink.

### Mode A: scalar probes as a one-value response channel

For discovery, the exploit makes one synthetic post with ID zero. Its
<code>post_content</code> expression is:

    CONCAT(
        <random start marker>,
        COALESCE(CAST((<scalar subquery>) AS CHAR), <NULL marker>),
        <random end marker>
    )

The posts REST controller prepares this synthetic row like a normal post and
returns the rendered content. The client recursively searches the JSON response
for the two markers and extracts the value between them.

This is not classic blind SQL injection. It does not infer one character at a
time from timing or Boolean differences. A scalar subquery is returned in a
single normal REST response. The PoC uses these probes to learn:

- the current database name;
- all posts/options table pairs and the one whose <code>home</code> option
  matches the REST index;
- the exact posts-table column names and order;
- users/usermeta table pairs, including multisite layouts;
- a user ID carrying the site-specific serialized
  <code>administrator</code> capability, with a user-level fallback;
- the IDs, names, and success state of newly created oEmbed cache rows.

It intentionally does **not** extract password hashes, authentication cookies,
nonces, or WordPress salts. The administrator ID is not an authentication
secret; it is data needed to make the forged Customizer setting run under the
right in-memory capability context.

Representative scalar expressions are:

~~~sql
-- Identify posts/options table pairs in the current database.
SELECT GROUP_CONCAT(p.TABLE_NAME)
FROM information_schema.TABLES AS p
WHERE p.TABLE_SCHEMA = DATABASE()
  AND RIGHT(p.TABLE_NAME, 5) = 'posts'
  AND EXISTS (
      SELECT 1
      FROM information_schema.TABLES AS o
      WHERE o.TABLE_SCHEMA = p.TABLE_SCHEMA
        AND o.TABLE_NAME =
            CONCAT(LEFT(p.TABLE_NAME, CHAR_LENGTH(p.TABLE_NAME) - 5), 'options')
  )

-- Select the site among possible WordPress table prefixes.
SELECT option_value
FROM <candidate_prefix>options
WHERE option_name = 'home'
ORDER BY option_id
LIMIT 1

-- Verify the exact positional UNION schema.
SELECT GROUP_CONCAT(COLUMN_NAME ORDER BY ORDINAL_POSITION)
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = '<selected_prefix>posts'

-- Find an administrator ID without reading its password hash.
SELECT u.ID
FROM <users_table> AS u
JOIN <usermeta_table> AS m ON m.user_id = u.ID
WHERE m.meta_key = '<site_prefix>capabilities'
  AND LOCATE('s:13:"administrator";b:1;', m.meta_value) > 0
ORDER BY u.ID
LIMIT 1
~~~

On multisite, a site's posts/options tables can use a numbered prefix while
users/usermeta remain global. The PoC therefore discovers users/usermeta pairs
separately and searches for the selected site's capability key. If the
serialized role fragment is absent, it also checks that site's
<code>user_level</code> metadata for an administrator-level account.

Each expression is still wrapped inside the marker-bearing
<code>post_content</code> scalar described above. These are not separate direct
database connections.

### Mode B: full rows as an object-cache programming channel

The decisive poison query UNIONs six rows. Their IDs are not arbitrary: each is
the positive ID of a real oEmbed cache post already present in the database.
Every other field is attacker-selected.

On the non-split path, <code>WP_Query</code> obtains the full database result,
converts each result to a <code>WP_Post</code>, and calls
<code>update_post_caches()</code>. With WordPress's default non-persistent
object cache, those forged objects now occupy the <code>posts</code> cache group
for the remainder of this PHP request:

    database row ID 42:  oembed_cache / publish / harmless HTML
    cached object ID 42: customize_changeset / future / forged JSON

No malicious row has yet been written to the database. But
<code>get_post(42)</code> returns the cached forged object. This distinction—
physical row versus cached object with the same ID—is the central exploitation
primitive.

Core uses <code>wp_cache_add_multiple()</code> here, not an unconditional
overwrite. The selected IDs therefore must not already have real objects in the
current request's posts cache. Seeding happens in earlier physical requests;
the default object cache disappears between them, and the attack request avoids
touching those six IDs before the poison query. A persistent cache or a
theme/plugin that preloads the IDs can make the real objects win the
“add-if-absent” race and is another reason the PoC diagnoses rather than assumes
successful poisoning.

The official vulnerable query and caching behavior can be reviewed in the
[7.0.1 WP_Query source](https://core.svn.wordpress.org/tags/7.0.1/wp-includes/class-wp-query.php).

## 4. Preparing six real IDs

The forged objects need positive IDs that already exist. Core update functions
do not treat a purely synthetic ID-zero REST row as an existing post, and the
later oEmbed refresh must target a durable cache record.

The PoC finds one public post or page through the REST API. It constructs six
same-site URLs by adding unique query markers, then uses six scalar-row posts
whose content contains:

    [embed]https://target.example/public-post/?cache_session=<unique>[/embed]

Preparing the REST response applies WordPress content filters. The normal
<code>WP_Embed</code> path fetches the same-site URL and inserts a real
<code>oembed_cache</code> row for each unique cache key. The PoC does not assume
the resulting IDs or <code>post_name</code> MD5 values. After every seed it
queries the newly allocated range and requires exactly one successful cache
row.

This preparation has two benefits:

- the six IDs are guaranteed to refer to physical rows which
  <code>wp_update_post()</code> can update; and
- their real database state is harmless until a forged object with the same ID
  is read from the request-local cache.

The row's <code>post_name</code> depends on the URL plus embed dimensions.
Themes or filters can change those dimensions, so calculating the name from a
hard-coded width/height is brittle. Discovering the actual row also detects
<code>{{unknown}}</code>, which means the target's server-side callback could
not fetch or trust its own public URL.

## 5. The forged object graph

The six real cache rows are assigned these logical roles:

| Role | Forged type/status | Forged parent | Why it exists |
|---|---|---:|---|
| primary | <code>oembed_cache/publish</code> | changeset | Stale oEmbed object whose refresh starts a trusted update |
| changeset | <code>customize_changeset/future</code> | primary_peer | Carries forged Customizer JSON and becomes published |
| primary_peer | <code>oembed_cache/publish</code> | changeset | Completes a loop below primary |
| nav | <code>page/auto-draft</code> | parse | Passes the nav-created-post sanitizer and starts the second loop |
| parse | <code>request/parse</code> | parse_peer | Produces dynamic hook <code>parse_request</code> |
| parse_peer | <code>request/parse</code> | parse | Completes the second loop |

The parent topology is:

~~~mermaid
flowchart LR
    P[primary<br/>oembed_cache / publish] --> C[changeset<br/>customize_changeset / future]
    C --> PP[primary_peer<br/>oembed_cache / publish]
    PP --> C

    N[nav<br/>page / auto-draft] --> R[parse<br/>request / parse]
    R --> RP[parse_peer<br/>request / parse]
    RP --> R
~~~

The current post is deliberately outside each actual cycle:

    primary -> (changeset <-> primary_peer)
    nav     -> (parse <-> parse_peer)

That shape selects a special branch of
<code>wp_check_post_hierarchy_for_loops()</code>. When the discovered loop does
not contain the post currently being updated, core iterates the loop members
and calls:

~~~php
wp_update_post(
    array(
        'ID'          => $loop_member,
        'post_parent' => 0,
    )
);
~~~

Those nested updates are the mechanism that converts cached fiction into
physical database state.

## 6. From the poisoned cache to a published changeset

### The fire row

Immediately after the six-row poison query, the inner batch executes another
confused posts request. Its UNION returns one transient ID-zero post containing
an embed shortcode for the URL associated with <code>primary</code>.

The cached forged primary object has an old
<code>post_modified_gmt</code>. <code>WP_Embed</code> therefore considers its
cached result stale, refreshes the same-site embed, and calls an update on the
real primary ID.

### Why a small trusted update persists all forged fields

<code>wp_update_post()</code> does not retrieve only the field it intends to
change. Its first operation is:

~~~php
$post = get_post( $postarr['ID'], ARRAY_A );
~~~

It then merges the caller's small update over all of those “original” fields.
Because <code>get_post()</code> hits the poisoned object cache, the original
fields are the attacker's post type, status, content, dates, author, and parent.
The innocent oEmbed-content update is therefore merged into a forged full post
and passed to <code>wp_insert_post()</code>.

The primary's parent path enters the changeset/primary-peer cycle. Core repairs
the cycle by recursively calling <code>wp_update_post()</code> on its members
with only <code>post_parent=0</code>. Each nested call repeats the same
cache-backed merge. As a result, the physical changeset row is rewritten from
a harmless oEmbed cache record into the forged
<code>customize_changeset</code>.

### Why <code>future</code> becomes <code>publish</code>

The forged changeset has:

    post_type     = customize_changeset
    post_status   = future
    post_date_gmt = 2000-01-01 00:00:00

During insertion/update, core normalizes a future post whose scheduled time is
less than one minute ahead of the current time to <code>publish</code>. A date
in 2000 deterministically takes that branch. The ordinary
<code>transition_post_status</code> action then invokes
<code>_wp_customize_publish_changeset()</code>, registered by core for
Customizer changesets.

The relevant merge, date normalization, hierarchy repair, and transition code
is in the official
[7.0.1 post source](https://core.svn.wordpress.org/tags/7.0.1/wp-includes/post.php).

## 7. Using Customizer as an administrator-context gadget

The changeset content has one setting:

~~~json
{
  "nav_menus_created_posts": {
    "value": [123],
    "type": "option",
    "user_id": 1,
    "date_modified_gmt": "2000-01-01 00:00:00"
  }
}
~~~

Here <code>123</code> is the discovered nav role ID and <code>1</code> is an
example only; the exploit discovers an administrator-capable user ID for the
site and does not assume that it is one.

### Why an ID is enough

Customizer changesets normally store the user who wrote each setting. When a
changeset is later published, possibly by cron, WordPress wants save-time
filters and KSES to behave as they would for the original author. The manager
therefore records each setting's stored <code>user_id</code> and, immediately
before calling that setting's <code>save()</code>, executes:

~~~php
wp_set_current_user( $setting_user_ids[ $setting_id ] );
$setting->save();
~~~

It restores the original user afterward. The source comments explain that an
additional capability check is omitted because a legitimate setting was
expected to have been checked when written into the changeset. The forged
changeset bypasses that earlier trust boundary: it supplies both the setting
and its claimed author.

This does not authenticate as the administrator and does not recover any
administrator credential. It creates a short-lived **in-memory current-user
context** inside a trusted publication routine. See
[WP_Customize_Manager in 7.0.1](https://core.svn.wordpress.org/tags/7.0.1/wp-includes/class-wp-customize-manager.php).

### Why <code>nav_menus_created_posts</code> is useful

The setting's sanitizer accepts post IDs only when:

- the cached object looks like <code>auto-draft</code> or <code>draft</code>;
- its post type is registered; and
- the current user can publish and edit it.

The forged nav object is <code>page/auto-draft</code>, and the current user is
temporarily the discovered administrator, so those checks pass.
<code>save_nav_menus_created_posts()</code> then publishes nav with
<code>wp_update_post()</code>. The sanitizer is not “missing authentication” in
normal use; it is making correct decisions about a forged cached object under a
forged changeset-author context.

## 8. From the second cycle to <code>parse_request</code>

Publishing nav follows its poisoned parent to the
parse/parse-peer cycle. Hierarchy repair again performs nested updates from the
forged cache. Both objects have:

    post_status = parse
    post_type   = request

WordPress's transition function always fires the dynamic action:

~~~php
do_action(
    "{$new_status}_{$post->post_type}",
    $post->ID,
    $post,
    $old_status
);
~~~

This hook also fires on later updates where old and new statuses are identical.
Therefore an update of a forged <code>request/parse</code> object invokes:

    parse_request

Core's default filters include:

~~~php
add_action( 'parse_request', 'rest_api_loaded' );
~~~

This is the direct RCE-chain gadget. It is not a search for a literal call to
<code>eval()</code>, <code>system()</code>, <code>exec()</code>, a template
include, or a vulnerable plugin. The object forgery synthesizes a **dynamic
core hook name** which calls the normal REST bootstrap at an unsafe point in
the current call stack.

## 9. Re-entering REST while the administrator is current

The exploit sends its physical request to:

    /index.php?rest_route=/batch/v1

The global WordPress query object therefore still contains:

    rest_route = /batch/v1

When the synthetic <code>parse_request</code> action calls
<code>rest_api_loaded()</code>, the function reads that global route and calls
<code>WP_REST_Server::serve_request('/batch/v1')</code> again. In the vulnerable
versions, there is no guard against starting a fresh top-level REST serve while
the same server is already dispatching.

Crucially, this happens synchronously inside the Customizer setting's
<code>save()</code>. The later restoration of the anonymous user has not run.
The call stack is approximately:

~~~text
outer anonymous REST dispatch
  posts response applies embed
    update primary
      repair first cycle
        publish changeset
          Customizer: set current user = administrator
            save nav_menus_created_posts
              update nav
                repair second cycle
                  transition request/parse
                    do_action("parse_request")
                      rest_api_loaded()
                        serve original /batch/v1 again AS CURRENT ADMIN
~~~

### Why REST cookie authentication does not zero the user

On a normal anonymous REST request without a nonce,
<code>rest_cookie_check_errors()</code> sets current user to zero. But its first
relevant branch says, in effect:

~~~php
if ( true !== $wp_rest_auth_cookie && is_user_logged_in() ) {
    return $result;
}
~~~

The reentrant call already has a nonzero in-memory user and cookie
authentication was not selected. The function assumes some other
authentication mechanism established that user and preserves it. That is
reasonable in ordinary internal dispatch, but here the identity came from the
forged changeset.

### Full inner batch layout

The attack stage uses this shifted inner list:

| Original index | Carrier/target request | Handler used after shift |
|---:|---|---|
| 0 | malformed <code>:</code> | error |
| 1 | widget carrier whose body contains generated username, password, email, and administrator role | users-create handler matched from index 2 |
| 2 | <code>POST /wp/v2/users</code> | widget handler matched from index 3 |
| 3 | widget carrier containing six-row poison SQL | posts handler matched from index 4 |
| 4 | <code>GET /wp/v2/posts</code> | widget handler matched from index 5 |
| 5 | widget carrier containing fire-row SQL | posts handler matched from index 6 |
| 6 | <code>GET /wp/v2/posts</code> | no useful following match |

On the first, anonymous pass, index 1 normally returns
<code>rest_cannot_create_user</code>. That error is expected: execution
continues to the poison and fire queries. Those queries reach the Customizer
gadget and re-enter the same body.

On the nested pass, index 1 runs before the poison query and now sees the
temporary administrator. Its permission callback accepts
<code>create_users</code>, and core creates the supplied administrator account.

The six poison SELECT arms include:

~~~sql
FROM DUAL
WHERE NOT EXISTS (
    SELECT 1
      FROM <discovered users table>
     WHERE user_login = <generated username>
)
~~~

The generated user exists by the time the nested pass reaches the poison
request, so the UNION returns no forged rows on that pass. The hierarchy repair
has also broken the parent cycles. These two one-shot conditions stop an
unbounded reentry loop.

Finally, <code>rest_api_loaded()</code> calls <code>die()</code> after serving.
That abandons the suspended outer Customizer stack, but the MySQL writes already
made under normal autocommit—including the administrator—remain persistent.

### Sequence diagram

~~~mermaid
sequenceDiagram
    participant A as Anonymous client
    participant R as REST batch server
    participant Q as WP_Query / MySQL
    participant C as WP object cache
    participant P as Post update/hierarchy
    participant U as Customizer
    participant N as Nested REST serve

    A->>R: POST /index.php?rest_route=/batch/v1
    R->>R: Outer and inner match arrays shift
    R->>R: users-create attempt as anonymous (401)
    R->>Q: Poison GET with scalar author_exclude
    Q-->>R: Six forged 23-column rows
    R->>C: Cache six forged WP_Post objects
    R->>Q: Fire GET returns ID-zero embed post
    R->>P: oEmbed refresh updates primary real ID
    P->>C: get_post() returns forged fields
    P->>P: Repair first parent cycle
    P->>U: Publish forged changeset
    U->>U: wp_set_current_user(real administrator ID)
    U->>P: Publish forged nav object
    P->>P: Repair second parent cycle
    P->>R: Fire dynamic parse_request action
    R->>N: serve_request(/batch/v1) re-enters same body
    N->>N: users-create handler now passes
    N->>Q: INSERT new administrator
    N-->>A: Top-level reentry eventually terminates via die()
~~~

## 10. Administrator creation versus RCE

The core chain itself yields an authenticated administrator account. That is
already a complete site compromise, but an administrator is not automatically
an operating-system shell in every deployment.

On a stock installation where WordPress may modify the plugin directory, the
PoC performs the standard authenticated workflow:

1. Log in through <code>wp-login.php</code> with the generated credentials.
2. Load the core plugin-upload page and extract its nonce.
3. Upload an in-memory ZIP containing a small PHP plugin file.
4. Request the plugin PHP file directly.
5. Send base64-encoded PHP source to its <code>eval()</code> parameter.
6. For ordinary command mode, evaluate a
   <code>passthru(base64_decode(...))</code> snippet.

Plugin activation is not required for a directly requested PHP file. The
current PoC installs the proof endpoint at
<code>wp2shell/wp2shell.php</code>; the plugin name has no bearing on the
vulnerability.

Other post-administrator paths—theme editing, plugin editing, configuration
changes, installing a different plugin, or application-level data theft—depend
on site policy and filesystem access. The pre-authentication boundary is crossed
before any of them.

## 11. Why the nested response can look misleading

An attack response may contain all of the following:

- one or more localized <code>parse_path_failed</code> errors;
- <code>rest_cannot_create_user</code> with status 401;
- a normal public posts response;
- irrelevant widget errors or empty responses; and
- a truncated or unexpectedly terminated JSON envelope.

The malformed-path response is the index-shift primitive, not evidence that the
request was rejected as a whole. Likewise, the first user-creation denial is
the expected anonymous pass. Success depends on the later fire query reaching
the reentrant pass.

If the final administrator login fails, the useful question is not “did the
outer users request return 401?” It should. The useful stage checks are:

1. Did the marker probe prove the full-row projection?
2. Did six successful oEmbed cache rows get created?
3. Did the changeset role's physical row remain
   <code>oembed_cache</code>, become an unpublished changeset, or become
   <code>customize_changeset/publish</code>?
4. If it published, did the second hierarchy transition invoke
   <code>parse_request</code>?
5. During reentry, was the temporary current user still administrator-capable?
6. Did user creation persist before <code>rest_api_loaded()</code> terminated?

This is why [wp2shell.py](./wp2shell.py) reports projection, discovered tables,
administrator source, cache IDs, changeset state, login verification, plugin
upload, endpoint URL, PHP runtime, and command output instead of treating one
HTTP status as the verdict.

## 12. The permanent fixes

The 6.9.5 and 7.0.2 patches break the demonstrated chain at three independent
links. The local 7.0.1-to-7.0.2 comparison is available in
[diffs/full.diff](./diffs/full.diff).

### Fix A: sanitize every <code>author__not_in</code> shape

The fixed code calls:

~~~php
$author__not_in_id_list =
    wp_parse_id_list( $query_vars['author__not_in'] );
~~~

It sorts and interpolates only the resulting integer list. This handles arrays
and scalars through one canonical path. A UNION string is reduced to integer
tokens; SQL syntax cannot survive into the <code>NOT IN</code> clause.

**Verdict:** this independently stops the SQL injection and object forging,
even if request/handler confusion is found elsewhere.

### Fix B: preserve parallel-array alignment

For a malformed request, the fixed match-building loop now appends:

~~~php
$matches[] = $single_request;
~~~

The error acts as a placeholder. All three arrays retain the same index space,
so carrier A can no longer receive target B's route and handler.

**Verdict:** this independently stops both outer and inner confusion. The
nested GET is validated against the real batch schema, and the raw widget
scalar cannot reach the posts handler.

### Fix C: reject a second top-level REST serve during dispatch

The fixed <code>rest_api_loaded()</code> returns early when the global REST
server reports that it is already dispatching. The server's
<code>serve_request()</code> also returns false under the same condition.
Legitimate internal subrequests can still use <code>dispatch()</code>.

The existing dispatch stack is nonempty while callbacks are executing, so the
synthetic <code>parse_request</code> action cannot start another top-level cycle
or execute the trailing <code>die()</code>.

**Verdict:** this independently stops the temporary-identity reentry used to
create the administrator, even if an attacker could still forge the object
graph.

The official fixed sources are:

- [WordPress 6.9.5 WP_Query](https://core.svn.wordpress.org/tags/6.9.5/wp-includes/class-wp-query.php)
- [WordPress 6.9.5 REST server](https://core.svn.wordpress.org/tags/6.9.5/wp-includes/rest-api/class-wp-rest-server.php)
- [WordPress 6.9.5 REST bootstrap](https://core.svn.wordpress.org/tags/6.9.5/wp-includes/rest-api.php)
- [WordPress 7.0.2 WP_Query](https://core.svn.wordpress.org/tags/7.0.2/wp-includes/class-wp-query.php)
- [WordPress 7.0.2 REST server](https://core.svn.wordpress.org/tags/7.0.2/wp-includes/rest-api/class-wp-rest-server.php)
- [WordPress 7.0.2 REST bootstrap](https://core.svn.wordpress.org/tags/7.0.2/wp-includes/rest-api.php)

## 13. Audit of the proposed mitigations

The advisory proposes updating, or temporarily blocking anonymous access to
the REST API/batch route. Those recommendations are sound when implemented as
described, but their scope matters.

| Control | Does it stop this PoC? | What it actually protects | Limitations |
|---|---|---|---|
| Update to 6.9.5 or 7.0.2 | **Yes** | Fixes SQL construction, array alignment, and top-level REST reentry | This is the durable solution. Verify the running core version and integrity, not only a dashboard update message. |
| Reject all anonymous REST requests before dispatch | **Yes** | Prevents the initial anonymous batch callback | Must run early and cover the batch namespace. It can break public REST consumers, block editor features, and affect integrations. Treat as temporary. |
| Remove or deny the <code>/batch/v1</code> route to anonymous callers | **Yes** | Removes the physical entry point used by both desync layers | A plugin that merely restricts users or posts endpoints is insufficient; the batch callback itself must be unreachable. |
| WAF/reverse-proxy block of the batch route | **Yes, if semantic and normalized** | Stops the only inbound physical request before WordPress | Match both pretty-permalink and query routing, decode once according to server behavior, handle trailing slash and query order, and reject encoded equivalents. A literal search only for <code>?rest_route=/batch/v1</code> may miss <code>&rest_route=...</code>, <code>index.php</code> forms, or encoded values. |
| WAF signature for <code>UNION</code>, <code>author_exclude</code>, or path <code>:</code> | Often, not reliably | Detects this known payload shape | Encoding, comments, case, alternate malformed paths, and future carriers make signatures secondary controls. Blocking the batch route is much stronger. |
| Disable the public posts route | This PoC stops | Removes its chosen handler and response renderer | The request-confusion bug remains, and other callbacks may be useful. Large compatibility cost. |
| Disable widgets REST | This carrier stops | Removes the current permissive carrier | It is not a root fix; another batch-enabled route with useful weakly typed parameters/body could replace it. |
| Persistent external object cache | Current full-row poison normally stops | Forces <code>WP_Query</code>'s ID-only split and may retain real post objects | Accidental incompatibility, not a security guarantee. Configuration/plugins can affect query splitting, and both core vulnerabilities remain. Do not deploy Redis merely as this patch. |
| Force <code>split_the_query=true</code> | Current 23-column object forge stops | Fetches IDs then primes real objects | Query filters are mutable application code and do not repair REST confusion or the scalar SQL sink. |
| Change the posts projection/schema | Current positional UNION likely fails | Breaks the exploit's assumed 23-column mapping | Unsupported, brittle, and potentially destructive to WordPress/plugins. Not a mitigation strategy. |
| Block loopback HTTP or oEmbed | Current trigger/seed path stops | Prevents creation/refresh of the chosen real objects | Breaks legitimate functionality; a different object consumer could replace this gadget. Self-connectivity is an operational assumption, not a security boundary. |
| <code>DISALLOW_FILE_MODS</code> plus read-only plugin/theme filesystem | Plugin-upload RCE tail stops | Prevents the newly created admin from installing/editing executable PHP through normal core paths | The attacker still has an administrator account and application-level control. Existing writable/uploaded executable paths or vulnerable plugins may provide alternatives. |
| <code>DISALLOW_FILE_EDIT</code> alone | Usually **no** | Disables dashboard theme/plugin editors | It does not necessarily disable plugin installation/upload. Use <code>DISALLOW_FILE_MODS</code> and filesystem policy for that boundary. |
| Least-privilege WordPress DB user without MySQL <code>FILE</code> | **No** | Prevents file-writing SQL techniques | This chain never uses <code>FILE</code>, stacked writes, or injected UPDATE. It needs the ordinary SELECT/INSERT/UPDATE privileges WordPress already has. |
| Restrict <code>information_schema</code> visibility | May break automatic discovery | Hides prefix/schema metadata from the PoC | A known or configured prefix removes much of this obstacle. It does not fix the injection. |
| Maintenance mode | Usually **no** | Replaces ordinary front-end responses | REST routes and directly requested plugin files commonly remain reachable. The local lab returned maintenance for the index while the eval endpoint remained accessible. |
| <code>disable_functions</code> | **No** for admin/PHP eval; maybe for plain OS command mode | Removes selected internal function names from normal PHP lookup | Not an OS sandbox and explicitly not treated by PHP as a security boundary. It is discussed separately below. |

### WAF implementation test

A defender should test a temporary batch block against all ways their own
WordPress/front controller accepts the same semantic route, including:

- pretty REST paths;
- <code>index.php</code> query routing;
- the parameter appearing first or later in the query string;
- percent-encoded route separators;
- a trailing slash; and
- reverse-proxy rewrites before versus after URL normalization.

The WAF need not observe the internal reentry: if it blocks the original
network request, there is no PHP call stack to re-enter. Conversely, once the
physical request reaches WordPress, the nested <code>serve_request()</code> is
an in-process function call and does not traverse the WAF a second time.

## 14. <code>disable_functions</code>: a barrier, not a boundary

If <code>passthru</code> and <code>system</code> are disabled, the ordinary
<code>--exec-cmd</code> tail cannot invoke them by name. That is a useful
operational barrier: it breaks a commodity PHP web shell and forces an attacker
to find another primitive.

It does **not** undo any earlier stage of this chain:

- the SQL query still runs;
- the object graph still publishes;
- the reentrant REST request still creates an administrator;
- the administrator may still upload PHP if file modifications are enabled; and
- <code>eval()</code>, database, filesystem, and network APIs remain available
  unless separately restricted.

<code>disable_functions</code> operates at PHP's function-exposure layer. Since
PHP 8 the definitions are removed so a userland replacement may be declared, but
it is not syscall filtering or process isolation. See the
[PHP core INI documentation](https://www.php.net/manual/en/ini.core.php#ini.disable-functions).

That distinction is why the packaged PoC can cross it. Once the eval endpoint
exists, the client sends a separate PHP-engine post-exploit that triggers a
use-after-free in PHP's legacy <code>Serializable</code> path and either recovers
the native <code>zif_system</code> handler to run commands as the web user, or
pivots to native code, ROP, and a root shell. That post-exploitation chain is a
distinct component, not part of the WordPress vulnerability, and it is documented
in full in [FULL_CHAIN_WRITEUP.md](./FULL_CHAIN_WRITEUP.md).

The driver exposes it through restricted-runtime actions:

- <code>--uaf-exec</code>, <code>--uaf-connect</code>, <code>--uaf-bash-connect</code>: command or reverse shell as the web user, bypassing <code>disable_functions</code> ([local_exploit.php](./local_exploit.php)).
- <code>--pic-file</code>: run an arbitrary PIC blob through the ROP path ([rop_serializable.php](./rop_serializable.php)).
- <code>--priv-exec</code>, <code>--priv-shell</code>: escalate to root through the packaged Copy Fail helper.

See [../README.md](../README.md) for how to run each mode.

## 15. PoC assumptions and likely failure points

The advisory's “no prerequisites” claim describes a stock affected
installation: no vulnerable plugin, existing login, DB <code>FILE</code>
privilege, password cracking, or prior shell is required. A particular PoC can
still have environmental assumptions.

| Stage | Assumption in the current PoC | Typical failure signal |
|---|---|---|
| Target discovery | Public REST index responds as WordPress | Non-JSON index, proxy block, maintenance plugin intercept |
| Version display | HTML/feed/readme exposes a version string | Version prints unknown; this alone does not prove safety |
| Batch entry | Anonymous <code>/batch/v1</code> reaches vulnerable core; max batch size is at least seven | 401/403 from an early REST policy, route missing, schema max-items error |
| Carrier | Core widgets route is registered and batch-enabled | Widget route/match errors |
| SQL reachability | Vulnerable scalar sink and no filter rewrites it | Marker absent, SQL/database error |
| Projection | Full, unfiltered 23-column <code>wp_posts.*</code> query | UNION column error or projection diagnostic |
| Object cache | Default non-persistent cache and forged IDs not already cached in this request | Poison query returns rows but later <code>get_post()</code> sees real objects |
| Metadata discovery | MySQL/MariaDB exposes relevant current-schema metadata | Prefix/schema/admin probe returns null |
| Administrator source | At least one site administrator is represented in usermeta | Capability and user-level probes find no ID |
| Embed seed | At least one public post/page and normal content/embed filters | No public link or no new oEmbed cache row |
| Loopback | WordPress can fetch and trust its own marked public URL | New row contains <code>{{unknown}}</code>; common with private hostnames or self-signed HTTPS |
| Hierarchy/Customizer | Core hooks are present and plugins do not short-circuit updates/settings | Changeset remains oEmbed, remains future, or publishes without reentry |
| Request lifetime | PHP, proxy, and web server allow the chained synchronous work to finish | Client/proxy/FPM timeout, truncated response |
| Admin verification | Login redirects/cookies are conventional and no additional login gate blocks the new account | DB row exists but canonical login test fails |
| Plugin tail | File modifications are allowed and plugin directory is writable | No upload nonce, filesystem/FTP prompt, install failure |
| Plain command | <code>passthru</code> is available | PHP runtime reports disabled functions; use OS containment, not assumptions |
| Fake-Closure UAF path | Adapted package: PHP 8.1 NTS, 64-bit Unix, x86_64/aarch64, legacy <code>Serializable</code> support, and compatible allocator/runtime; upstream declares a broader 8.0–8.5 range | Early compatibility rejection, worker crash, missing completion marker, callback timeout |
| ROP/PIC/root path | Packaged driver: PHP 8.1 NTS x86_64, readable live ELF metadata, required gadget patterns, and compatible helper/LPE environment | ELF validation failure, missing gadget, ROP marker absent, helper timeout, or root-stage result not observed |

### HTTPS and self-signed certificates

<code>--skip-tls-verify</code> affects only the Python client's TLS verification.
The oEmbed seed and trigger cause **the target WordPress process** to fetch its
own public URL. Python cannot change the target's CA store or HTTP transport
policy. A self-signed lab therefore needs one of:

- a certificate trusted inside the PHP/WordPress runtime;
- a same-site HTTP URL that WordPress is configured and permitted to fetch; or
- a lab-specific trust configuration.

This explains why the same exploit may work on one VM and stop at the oEmbed
stage on another even when their WordPress source is identical.

### Timeouts

The PoC's <code>--wait</code> controls how long its own HTTP client waits.
Larger values help when same-site oEmbed callbacks, DNS, PHP-FPM, or a reverse
proxy are slow. They cannot raise:

- PHP's <code>max_execution_time</code>;
- an Nginx/Apache/FastCGI upstream timeout;
- a load balancer timeout;
- a target-side socket timeout; or
- a callback listener/network timeout.

Values around 120 seconds are suitable for the lab; 180–300 seconds can help
diagnose a slow authorized VM. If the target itself kills the request at 60
seconds, setting the client to 300 only makes the client wait longer for a
failure.

## 16. Detection and incident response

### High-confidence request indicators

Inspect web/WAF request bodies, not only URLs, for:

- anonymous POST requests to a semantic <code>/batch/v1</code> route;
- nested <code>requests</code> arrays carried in a widgets request body;
- subrequest path <code>:</code> or repeated path-parse failures;
- GET subrequests appearing inside a batch schema that normally forbids GET;
- <code>author_exclude</code> on a widgets route;
- scalar SQL punctuation, <code>UNION ALL SELECT</code>, or a SQL comment in
  that parameter;
- <code>per_page=500</code> and <code>orderby=none</code> on the widget
  carrier; and
- several same-site public-post requests with unique query markers immediately
  after the batch request begins.

### Host and database indicators

Look for:

- multiple <code>oembed_cache</code> posts created within seconds;
- those IDs changing type/status to
  <code>customize_changeset</code>, <code>page</code>, or the unusual
  <code>request/parse</code> combination;
- a new administrator in <code>wp_users</code> and site-specific capability
  usermeta;
- a fresh plugin directory and direct requests to its PHP file;
- access to plugin-upload administration followed immediately by direct PHP
  POSTs; and
- PHP-FPM worker crashes if a memory-corruption post-exploit was attempted.

WordPress does not provide a comprehensive immutable administrator-action audit
log by default. <code>wp_users.user_registered</code> gives a creation time,
but the stock dashboard does not normally present a full trustworthy creation
event history. Web logs, database audit/general logs, filesystem telemetry, and
a purpose-built audit plugin or external SIEM are more useful.

If exploitation is suspected, updating core is necessary but not sufficient.
Treat the site and PHP worker identity as compromised: preserve evidence,
remove unauthorized users/plugins only after collection, inspect other
persistence, rotate WordPress salts and credentials/secrets reachable by the
worker, and rebuild from known-good code where possible.

## 17. Reproducing the authorized local lab

For the ordinary PHP-FPM lab, the main entry point is:

~~~console
python3 wp2shell.py http://localhost:8080 --exec-cmd 'id; uname -a'
~~~

The current client uses named stages rather than a numbered request counter:
<code>Target check</code>, <code>Site discovery</code>,
<code>Cache preparation</code>, <code>Privilege trigger</code>,
<code>Administrator verification</code>, and
<code>WP2Shell installation</code>. Output prefixes have consistent meanings:
<code>[*]</code> is an action in progress, <code>[+]</code> is a verified
result, <code>[!]</code> is a warning or fallback, and <code>[-]</code> is a
failure.

To prove only the core administrator primitive:

~~~console
python3 wp2shell.py http://localhost:8080 --stop-after-admin
~~~

To enter the repeated HTTP command loop after upload:

~~~console
python3 wp2shell.py http://localhost:8080 --shell
~~~

The normal exploit and command loop need only [wp2shell.py](./wp2shell.py). That
same driver also exposes <code>--uaf-exec</code>, <code>--uaf-connect</code>, and
<code>--uaf-bash-connect</code>; those modes additionally need
[local_exploit.php](./local_exploit.php), discovered beside the script by
default. The packaged [docker/](./docker) lab below applies a restricted
<code>disable_functions</code> profile for exercising them.

For the packaged Apache/mod_php lab:

~~~console
./docker/setup.sh
python3 wp2shell.py http://localhost:8083 --stop-after-admin --wait 120
~~~

That Dockerfile builds WordPress 7.0.1 on PHP 8.1.34
<code>apache2handler</code>, exposes it on
<code>http://localhost:8083/</code>, and enables the restricted
<code>disable_functions</code> profile used by the UAF/ROP testing paths.
Operational notes, credentials, and cleanup commands are in
[docker/README.md](./docker/README.md).

Attach to an existing compatible eval endpoint without repeating the WordPress
chain:

~~~console
python3 wp2shell.py \
  --attach-url http://localhost:8080/wp-content/plugins/wp2shell/wp2shell.php \
  --shell
~~~

The command loop is not a PTY. Each command is a new HTTP request and shell
process; <code>cd</code> or exported variables do not persist automatically.

## 18. Concise root-cause statement

The complete vulnerability is the composition of three broken trust
assumptions:

1. **REST assumes positional identity:** validation, request objects, and route
   matches are stored separately but later paired by index even after one array
   was compacted.
2. **WP_Query assumes a declared type:** its SQL builder sanitizes
   <code>author__not_in</code> only if the caller actually supplied the
   documented array shape.
3. **Core consumers trust cached post identity:** updates, hierarchy repair,
   Customizer publication, and dynamic status hooks assume that a
   <code>WP_Post</code> found under a real ID reflects that row's legitimate
   state.

The first bug violates the second assumption; the SQL injection then violates
the third. Reentrant REST dispatch converts a temporary trusted execution
context into a persistent administrator, and ordinary administration converts
that account into executable PHP.

That is why describing this only as “an SQL injection” misses most of the
vulnerability—and why dumping credentials is neither necessary nor the
interesting use of the SQL primitive.

## Primary references

- [Searchlight Cyber disclosure](https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/)
- [WordPress 3.7.1 query source](https://core.svn.wordpress.org/tags/3.7.1/wp-includes/query.php)
- [WordPress 6.7 WP_Query](https://core.svn.wordpress.org/tags/6.7/wp-includes/class-wp-query.php)
- [WordPress 6.8 WP_Query](https://core.svn.wordpress.org/tags/6.8/wp-includes/class-wp-query.php)
- [WordPress 6.8.5 REST server](https://core.svn.wordpress.org/tags/6.8.5/wp-includes/rest-api/class-wp-rest-server.php)
- [WordPress 6.9 REST server](https://core.svn.wordpress.org/tags/6.9/wp-includes/rest-api/class-wp-rest-server.php)
- [WordPress 7.0.1 REST server](https://core.svn.wordpress.org/tags/7.0.1/wp-includes/rest-api/class-wp-rest-server.php)
- [WordPress 7.0.1 default filters](https://core.svn.wordpress.org/tags/7.0.1/wp-includes/default-filters.php)
- [PHP security classification](https://github.com/php/php-src/blob/master/SECURITY.md)
- [PHP <code>disable_functions</code> documentation](https://www.php.net/manual/en/ini.core.php#ini.disable-functions)
- [PHP <code>unserialize()</code> documentation](https://www.php.net/manual/en/function.unserialize.php)
