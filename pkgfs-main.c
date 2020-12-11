/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>
  Copyright (C) 2020       Andrew Chambers <ac@acha.ninja>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file LICENSE.
*/

#define FUSE_USE_VERSION 31
#define _GNU_SOURCE
#include "util.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <fuse.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

struct idxent {
  enum {
    IDX_DIR,
    IDX_FILE,
  } kind;
  char *true_path;
  size_t dir_ents_cap;
  size_t dir_ents_len;
  struct idxent **dir_ents;
};

static struct hashtable *idx_htab = NULL;

static void *pkgfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
  (void)conn;
  cfg->nullpath_ok = 1;
  cfg->entry_timeout = 60;
  cfg->attr_timeout = 60;
  cfg->negative_timeout = 60;
  return NULL;
}

static int pkgfs_getattr(const char *path, struct stat *stbuf,
                         struct fuse_file_info *fi) {
  int res;
  struct hashtablekey k;
  struct idxent *ent;

  (void)path;

  if (fi)
    res = fstat(fi->fh, stbuf);
  else {
    htabkey(&k, path, strlen(path));
    ent = htabget(idx_htab, &k);
    if (ent)
      res = lstat(ent->true_path, stbuf);
    else {
      res = -1;
      errno = ENOENT;
    }
  }
  if (res == -1)
    return -errno;

  return 0;
}

static int pkgfs_access(const char *path, int mask) {
  int res;
  struct hashtablekey k;
  struct idxent *ent;

  htabkey(&k, path, strlen(path));
  ent = htabget(idx_htab, &k);
  if (ent) {
    res = access(ent->true_path, mask);
    if (res == -1)
      return -errno;
  } else {
    return -ENOENT;
  }
  return 0;
}

static int pkgfs_readlink(const char *path, char *buf, size_t size) {
  int res;
  struct hashtablekey k;
  struct idxent *ent;

  htabkey(&k, path, strlen(path));
  ent = htabget(idx_htab, &k);
  if (ent) {
    res = readlink(ent->true_path, buf, size - 1);
    if (res == -1)
      return -errno;
  } else {
    return -ENOENT;
  }

  buf[res] = '\0';
  return 0;
}

static int pkgfs_opendir(const char *path, struct fuse_file_info *fi) {
  struct hashtablekey k;
  htabkey(&k, path, strlen(path));
  struct idxent *ent = htabget(idx_htab, &k);
  if (ent) {
    fi->fh = (unsigned long)ent;
    return 0;
  } else {
    return -ENOENT;
  }
}

static inline struct idxent *get_dirent(struct fuse_file_info *fi) {
  return (struct idxent *)(uintptr_t)fi->fh;
}

static int pkgfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags) {
  struct idxent *ent = get_dirent(fi);
  for (size_t i = 0; i < ent->dir_ents_len; i++) {
    if (filler(buf, strrchr(ent->dir_ents[i]->true_path, '/') + 1, NULL, 0, 0))
      break;
  }
  return 0;
}

static int pkgfs_releasedir(const char *path, struct fuse_file_info *fi) {
  (void)path;
  return 0;
}

static int pkgfs_open(const char *path, struct fuse_file_info *fi) {
  int fd;
  struct hashtablekey k;
  struct idxent *ent;

  htabkey(&k, path, strlen(path));
  ent = htabget(idx_htab, &k);
  if (ent) {
    fd = open(ent->true_path, fi->flags);
    if (fd == -1)
      return -errno;
  } else {
    return -ENOENT;
  }

  fi->fh = fd;
  return 0;
}

static int pkgfs_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
  int res;

  (void)path;
  res = pread(fi->fh, buf, size, offset);
  if (res == -1)
    res = -errno;

  return res;
}

static int pkgfs_read_buf(const char *path, struct fuse_bufvec **bufp,
                          size_t size, off_t offset,
                          struct fuse_file_info *fi) {
  struct fuse_bufvec *src;

  (void)path;

  src = malloc(sizeof(struct fuse_bufvec));
  if (src == NULL)
    return -ENOMEM;

  *src = FUSE_BUFVEC_INIT(size);

  src->buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
  src->buf[0].fd = fi->fh;
  src->buf[0].pos = offset;

  *bufp = src;

  return 0;
}

static int pkgfs_statfs(const char *path, struct statvfs *stbuf) {
  int res;
  struct hashtablekey k;
  struct idxent *ent;

  htabkey(&k, "/", 1);
  ent = htabget(idx_htab, &k);
  // Kind of bogus, but its unclear what we should do here.
  res = statvfs(ent->true_path, stbuf);
  if (res == -1)
    return -errno;

  return 0;
}

static int pkgfs_release(const char *path, struct fuse_file_info *fi) {
  (void)path;
  close(fi->fh);
  return 0;
}

static off_t pkgfs_lseek(const char *path, off_t off, int whence,
                         struct fuse_file_info *fi) {
  off_t res;
  (void)path;

  res = lseek(fi->fh, off, whence);
  if (res == -1)
    return -errno;

  return res;
}

static const struct fuse_operations pkgfs_oper = {
    .init = pkgfs_init,
    .getattr = pkgfs_getattr,
    .access = pkgfs_access,
    .readlink = pkgfs_readlink,
    .opendir = pkgfs_opendir,
    .readdir = pkgfs_readdir,
    .releasedir = pkgfs_releasedir,
    .open = pkgfs_open,
    .read = pkgfs_read,
    .read_buf = pkgfs_read_buf,
    .statfs = pkgfs_statfs,
    .release = pkgfs_release,
    .lseek = pkgfs_lseek,
};

static char *root = NULL;
static size_t root_len = 0;

static int add_to_index_nftw(const char *fpath, const struct stat *sb,
                             int tflag, struct FTW *ftwbuf) {
  // Add the dirent to the index.
  struct idxent *current_ent;

  switch (tflag) {
  case FTW_F:
  case FTW_SL:
  case FTW_D: {
    struct hashtablekey k;
    const char *kstr = fpath + root_len;
    size_t klen = strlen(kstr);
    if (klen == 0) {
      kstr = "/";
      klen = 1;
    }
    htabkey(&k, xstrdup(kstr), klen);
    struct idxent **pent = (struct idxent **)htabput(idx_htab, &k);
    if (!*pent) {
      *pent = xmalloc(sizeof(struct idxent));
      if (tflag == FTW_D) {
        (*pent)->kind = IDX_DIR;
      } else {
        (*pent)->kind = IDX_FILE;
      }
      (*pent)->true_path = strdup(fpath);
      (*pent)->dir_ents_cap = 0;
      (*pent)->dir_ents_len = 0;
      (*pent)->dir_ents = NULL;
    } else {
      free((void *)k.str);
    }
    current_ent = *pent;
    break;
  }
  case FTW_DNR:
    fprintf(stderr, "pkgfs: unable to read directory at %s, aborting\n", fpath);
    exit(1);
  case FTW_NS:
    fprintf(stderr, "pkgfs: unable to stat %s, aborting\n", fpath);
    exit(1);
  default:
    abort();
  }

  if (strcmp(fpath, root) != 0) {
    const char *fname = fpath + ftwbuf->base;
    const char *parent = fpath + root_len;
    const char *endslash = strrchr(parent, '/');
    assert(endslash != 0);
    struct hashtablekey k;
    size_t parent_len = endslash - parent;
    if (parent_len == 0) {
      parent = "/";
      parent_len = 1;
    }
    htabkey(&k, parent, parent_len);
    struct idxent *ent = htabget(idx_htab, &k);
    assert(ent != 0);

    if (ent->kind == IDX_DIR) {
      int exists = 0;

      for (size_t i = 0; i < ent->dir_ents_len; i++) {
        if (strcmp(fname, strrchr(ent->dir_ents[i]->true_path, '/') + 1) == 0) {
          exists = 1;
          break;
        }
      }

      if (!exists) {
        if (ent->dir_ents_cap == 0) {
          ent->dir_ents_cap = 64;
        } else if (ent->dir_ents_cap == ent->dir_ents_len) {
          ent->dir_ents_cap = ent->dir_ents_cap * 2;
        }
        ent->dir_ents =
            xreallocarray(ent->dir_ents, ent->dir_ents_cap, sizeof(char *));
        ent->dir_ents[ent->dir_ents_len++] = current_ent;
      }
    }
  }

  return 0;
}

static int isdir(const char *path) {
  struct stat statbuf;
  if (stat(path, &statbuf) != 0) {
    fprintf(stderr, "pkgfs: stat of %s failed: %s\n", path, strerror(errno));
    exit(1);
  }
  return S_ISDIR(statbuf.st_mode);
}

static void add_to_index(char *path) {
  fprintf(stderr, "pkgfs: adding %s to union index...\n", path);

  if (!isdir(path)) {
    fprintf(stderr, "pkgfs: union point %s is not a directory\n", path);
    exit(1);
  }

  root = realpath(path, NULL);
  if (!root) {
    perror("pkgfs: realpath");
    exit(1);
  }

  root_len = strlen(root);

  if (nftw(root, add_to_index_nftw, 128, FTW_PHYS) == -1) {
    perror("pkgfs: nftw");
    exit(1);
  }

  free(root);
  root = NULL;
  root_len = 0;
}

void del_idx_key(struct hashtablekey *k) { free((void *)k->str); }

void del_idx_ent(void *p) {
  struct idxent *ent = p;
  free(ent->true_path);
  for (size_t i = 0; i < ent->dir_ents_len; i++) {
    free(ent->dir_ents[i]);
  }
  free(ent->dir_ents);
  free(ent);
}

static struct options {
  const char *contents;
  int show_help;
} options;

#define OPTION(t, p)                                                           \
  { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {OPTION("--help", show_help),
                                              FUSE_OPT_END};

static void show_help(const char *progname) {
  printf("usage: %s [options] unions... <mountpoint>\n\n", progname);
  printf("File-system specific options:\n"
         "\n");
}

static char **prev_arg = NULL;
int pkgfs_opt_proc(void *data, const char *arg, int key,
                   struct fuse_args *outargs) {
  if (key == FUSE_OPT_KEY_NONOPT) {
    if (*prev_arg) {
      add_to_index(*prev_arg);
      free(*prev_arg);
    }
    *prev_arg = strdup(arg);
    return 0;
  }
  return 1;
}

int main(int argc, char *argv[]) {
  int ret;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

  idx_htab = mkhtab(65536);

  char *mnt_point = NULL;
  prev_arg = &mnt_point;
  /* Parse options */
  if (fuse_opt_parse(&args, &options, option_spec, pkgfs_opt_proc) == -1)
    return 1;

  if (mnt_point) {
    assert(fuse_opt_add_arg(&args, mnt_point) == 0);
    free(mnt_point);
  }

  /* When --help is specified, first print our own file-system
     specific help text, then signal fuse_main to show
     additional help (by adding `--help` to the options again)
     without usage: line (by setting argv[0] to the empty
     string) */
  if (options.show_help) {
    show_help(argv[0]);
    assert(fuse_opt_add_arg(&args, "--help") == 0);
    args.argv[0][0] = '\0';
  }

  fprintf(stderr, "pkgfs: starting fuse server...\n");
  ret = fuse_main(args.argc, args.argv, &pkgfs_oper, NULL);
  fuse_opt_free_args(&args);

  if (getenv("PKGFS_CLEANUP"))
    delhtab(idx_htab, del_idx_key, del_idx_ent);

  return ret;
}
