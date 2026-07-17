# Maglev primitives - incremental build-up

The four memory primitives, built up **one capability per file** so each step is
readable on its own. This is the same exploit as [`../poc3.js`](../poc3.js)
(the annotated all-in-one) and Stage 1 of [`../poc.html`](../poc.html), sliced into the four primitives in the order they are built.

| # | File | Adds |
|---|------|------|
| 1 | [`1_caged_read.js`](1_caged_read.js) | trigger => UAF => forge fake array => memory anchor => **caged read** |
| 2 | [`2_caged_write.js`](2_caged_write.js) | **caged write** (same fake array) |
| 3 | [`3_addrof.js`](3_addrof.js) | marker array + scan => **addrof** |
| 4 | [`4_fakeobj.js`](4_fakeobj.js) | **fakeobj**; verifies all four together |

## Run

```sh
/path/to/d8 --allow-natives-syntax --maglev --no-turbofan <poc_file>.js
```