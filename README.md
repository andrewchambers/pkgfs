# pkgfs 

A read only union filesystem for sets of read only directories.
directories are merged, files appear on a first in list order.

This file system was primarily designed for a package manager
that works by mounting many packages in a read only union, then creating
a chroot of the combined packages. The packages themselves are never edited
so we can safely keep the whole union index in memory.

## Example 

Mount three 

```
$ pkgfs -f -oauto_unmount,kernel_cache ./dir1 ./dir2 ./dir3 ./mnt
```

