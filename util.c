/*
Copyright © 2017-2020 Michael Forney

Permission to use, copy, modify, and/or distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.
*/

#include "util.h"
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *xstrdup(const char *s) {
  char *sdup;

  sdup = strdup(s);
  if (!s) {
    fprintf(stderr, "out of memory\n");
    exit(1);
  }

  return sdup;
}

void *xmalloc(size_t n) {
  void *p;

  p = malloc(n);
  if (!p) {
    fprintf(stderr, "out of memory\n");
    exit(1);
  }

  return p;
}

void *xreallocarray(void *p, size_t n, size_t m) {
  p = reallocarray(p, n, m);
  if (!p) {
    fprintf(stderr, "out of memory\n");
    exit(1);
  }

  return p;
}

struct hashtable {
  size_t len, cap;
  struct hashtablekey *keys;
  void **vals;
};

void htabkey(struct hashtablekey *k, const char *s, size_t n) {
  k->str = s;
  k->len = n;
  k->hash = murmurhash64a(s, n);
}

struct hashtable *mkhtab(size_t cap) {
  struct hashtable *h;
  size_t i;

  assert(!(cap & (cap - 1)));
  h = xmalloc(sizeof(*h));
  h->len = 0;
  h->cap = cap;
  h->keys = xreallocarray(NULL, cap, sizeof(h->keys[0]));
  h->vals = xreallocarray(NULL, cap, sizeof(h->vals[0]));
  for (i = 0; i < cap; ++i)
    h->keys[i].str = NULL;

  return h;
}

void delhtab(struct hashtable *h, void delk(struct hashtablekey *),
             void del(void *)) {
  size_t i;

  if (!h)
    return;
  if (del || delk) {
    for (i = 0; i < h->cap; ++i) {
      if (h->keys[i].str) {
        if (del)
          del(h->vals[i]);
        if (delk)
          delk(&h->keys[i]);
      }
    }
  }
  free(h->keys);
  free(h->vals);
  free(h);
}

static bool keyequal(struct hashtablekey *k1, struct hashtablekey *k2) {
  if (k1->hash != k2->hash || k1->len != k2->len)
    return false;
  return memcmp(k1->str, k2->str, k1->len) == 0;
}

static size_t keyindex(struct hashtable *h, struct hashtablekey *k) {
  size_t i;

  i = k->hash & (h->cap - 1);
  while (h->keys[i].str && !keyequal(&h->keys[i], k))
    i = (i + 1) & (h->cap - 1);
  return i;
}

void **htabput(struct hashtable *h, struct hashtablekey *k) {
  struct hashtablekey *oldkeys;
  void **oldvals;
  size_t i, j, oldcap;

  if (h->cap / 2 < h->len) {
    oldkeys = h->keys;
    oldvals = h->vals;
    oldcap = h->cap;
    h->cap *= 2;
    h->keys = xreallocarray(NULL, h->cap, sizeof(h->keys[0]));
    h->vals = xreallocarray(NULL, h->cap, sizeof(h->vals[0]));
    for (i = 0; i < h->cap; ++i)
      h->keys[i].str = NULL;
    for (i = 0; i < oldcap; ++i) {
      if (oldkeys[i].str) {
        j = keyindex(h, &oldkeys[i]);
        h->keys[j] = oldkeys[i];
        h->vals[j] = oldvals[i];
      }
    }
    free(oldkeys);
    free(oldvals);
  }
  i = keyindex(h, k);
  if (!h->keys[i].str) {
    h->keys[i] = *k;
    h->vals[i] = NULL;
    ++h->len;
  }

  return &h->vals[i];
}

void *htabget(struct hashtable *h, struct hashtablekey *k) {
  size_t i;

  i = keyindex(h, k);
  return h->keys[i].str ? h->vals[i] : NULL;
}

uint64_t murmurhash64a(const void *ptr, size_t len) {
  const uint64_t seed = 0xdecafbaddecafbadull;
  const uint64_t m = 0xc6a4a7935bd1e995ull;
  uint64_t h, k, n;
  const uint8_t *p, *end;
  int r = 47;

  h = seed ^ (len * m);
  n = len & ~0x7ull;
  end = ptr;
  end += n;
  for (p = ptr; p != end; p += 8) {
    memcpy(&k, p, sizeof(k));

    k *= m;
    k ^= k >> r;
    k *= m;

    h ^= k;
    h *= m;
  }

  switch (len & 0x7) {
  case 7:
    h ^= (uint64_t)p[6] << 48; /* fallthrough */
  case 6:
    h ^= (uint64_t)p[5] << 40; /* fallthrough */
  case 5:
    h ^= (uint64_t)p[4] << 32; /* fallthrough */
  case 4:
    h ^= (uint64_t)p[3] << 24; /* fallthrough */
  case 3:
    h ^= (uint64_t)p[2] << 16; /* fallthrough */
  case 2:
    h ^= (uint64_t)p[1] << 8; /* fallthrough */
  case 1:
    h ^= (uint64_t)p[0];
    h *= m;
  }

  h ^= h >> r;
  h *= m;
  h ^= h >> r;

  return h;
}
