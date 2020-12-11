#! /bin/sh
set -eux
gcc -O3 -Wall pkgfs-main.c util.c `pkg-config fuse3 --cflags --libs` -o pkgfs