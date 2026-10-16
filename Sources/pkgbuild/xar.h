/*
 * Copyright (c) 2026 Sunneva N. Mariu <sunnevanattsol@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef XAR_H
#define XAR_H

#include <stddef.h>
#include <stdint.h>

/* An extended attribute carried alongside a file in the archive heap. */
struct xar_xattr {
	const char *name;
	const void *value;
	size_t vlen;
};

/* One entry in a xar archive heap. */
struct xar_entry {
	const char *name;       /* path within the archive, e.g. "Payload" */
	const char *encoding;   /* "application/x-gzip" or "application/octet-stream" */
	const void *data;       /* raw, uncompressed bytes */
	size_t size;            /* uncompressed size of data */
	int compressed;         /* 1: zlib-compress when packing, 0: store raw */

	/*
	 * On-disk metadata.  pkgbuild materialises the BOM and Payload as
	 * temporary files and lets xar record their stat()/xattr metadata,
	 * while PackageInfo is added from memory and carries none.  When
	 * has_attr is set the table of contents reproduces that full per-file
	 * attribute block; otherwise only <data>/<type>/<name> are emitted.
	 */
	int has_attr;
	uint32_t mode;
	uint32_t uid, gid;
	char user[64];
	char group[64];
	uint64_t dev, ino;
	uint32_t ctime, mtime, atime, birthtime;

	struct xar_xattr xattrs[4];
	int nxattr;
};

/*
 * Build a pkgutil-valid xar archive from the given entries.
 * The archive checksum is sha1(toc_zlib); the layout matches a real
 * pkgbuild-produced package (creation-time, heap-relative <offset>s).
 * Returns a malloc'd buffer (caller frees) and sets *out_len.
 */
unsigned char *xar_build(const struct xar_entry *entries, int n,
    size_t *out_len);

/*
 * Materialise data as a temporary file, stat() it and read its extended
 * attributes (notably com.apple.provenance, which macOS stamps onto files
 * created by this process), filling e's on-disk metadata so the TOC matches
 * a real pkgbuild archive.  Sets e->data/e->size and e->has_attr.  Returns 0
 * on success, -1 on failure.
 */
int xar_entry_set_data_file(struct xar_entry *e, const void *data, size_t len);

/* Release the metadata (xattr name/value copies) allocated by
 * xar_entry_set_data_file. */
void xar_entry_free_meta(struct xar_entry *e);

/*
 * Read an existing xar package and print its table of contents
 * (file names + sizes). Returns 0 on success, -1 on a corrupt archive.
 */
int xar_dump(const unsigned char *pkg, size_t len);

#endif /* XAR_H */
