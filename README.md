Optimized implementation of twofish block cipher algorithm in C written by @drewcsillag

with stream encryption / decryption API similar to OpenSSL EVP.

Encryption supported:
- [x] twofish-256-ecb `twofish_256_ecb_init`
- [x] twofish-256-cbc `twofish_256_cbc_init`
- [x] twofish-192-ecb `twofish_192_ecb_init`
- [x] twofish-192-cbc `twofish_192_cbc_init`
- [x] twofish-128-ecb `twofish_128_ecb_init`
- [x] twofish-128-cbc `twofish_128_cbc_init`

bindings:
- [x] ruby

-----------

original README:


Twofish
-----------
Originally written around 2000-2001 or so.

A highly optimized implementation of the
[twofish](https://www.schneier.com/twofish.html) encryption algorithm
in C, and one not at all optimized in Python.

Basically, I use the Python version in `myref.py` to precompute some 
tables into `tables.h`.  From there, there are two C implementations.
The first in `opt.c`, I attempted to do some funky things in copying
the function and keying the function directly, as opposed to providing
keystate to the function.  It turns out, at least at the time, to not
be faster than the more sane version, *i.e. the one you should actually use*,
that is in `opt2.c`.  In fact, on more modern Linux versions, `opt.c`
probably doesn't even work because of the weird way it tries to do
things.

The Makefile builds the whole thing, and produces an executable named
`twofish-benchmark`.  If you want to incorporate this into your own
software, just kill the `main` function and have a blast.

The version in `myref.py` should be fairly readable, as it was designed
with the idea to reflect the algorithm's definition.  The optimized C
versions are not designed at all to be readable so much as fast.
