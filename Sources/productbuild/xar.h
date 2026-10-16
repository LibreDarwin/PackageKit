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

/*
 * One entry in a xar archive heap.  productbuild archives are a tree: a
 * top-level Distribution file plus one directory per component package
 * (e.g. root.pkg) whose children (Bom, Payload, PackageInfo) are nested
 * <file> elements.  Entries are supplied in depth-first pre-order, which
 * fixes their ids (id = index + 1).
 */
struct xar_entry {
	const char *name;       /* leaf name, e.g. "Payload" */
	const char *encoding;   /* "application/x-gzip" or "application/octet-stream" */
	const void *data;       /* raw, uncompressed bytes (NULL for directories) */
	size_t size;            /* uncompressed size of data */
	int compressed;         /* 1: zlib-compress when packing, 0: store raw */
	int is_dir;             /* 1: directory entry (no <data>), 0: file */
	int parent;             /* index of parent directory, or -1 for top level */

	/*
	 * On-disk metadata.  productbuild materialises the BOM and Payload as
	 * temporary files and lets xar record their stat()/xattr metadata,
	 * while PackageInfo and Distribution are added from memory and carry
	 * none.  Directories carry a synthetic all-zero block.  When has_attr
	 * is set the TOC reproduces the full per-file attribute block.
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
 * Build a pkgutil-valid xar product archive from the given entries.
 * The archive checksum is sha1(toc_zlib); the layout matches a real
 * productbuild-produced package (creation-time, heap-relative <offset>s,
 * data-before-ea per entry, ids in pre-order, top-level entries listed in
 * reverse and each directory's children listed forward).
 * Returns a malloc'd buffer (caller frees) and sets *out_len.
 */
unsigned char *xar_build(const struct xar_entry *entries, int n,
    size_t *out_len);

/*
 * Materialise data as a temporary file, stat() it and read its extended
 * attributes (notably com.apple.provenance, which macOS stamps onto files
 * created by this process), filling e's on-disk metadata so the TOC matches
 * a real productbuild archive.  Sets e->data/e->size and e->has_attr.
 * Returns 0 on success, -1 on failure.
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
