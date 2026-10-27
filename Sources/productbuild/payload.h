/*
 * Copyright (c) 2026 Sunneva N. Mariu <sunnevanattsol@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

/*
 * Generated from a source root directory.
 *   data         - gzip( cpio -o -H odc ) for the root's files
 *   size          - byte length of data
 *   uncompressed  - byte length of the raw cpio
 *   file_count    - number of cpio records (dirs + files + AppleDouble
 *                   sidecars, incl. "." but excluding the TRAILER!!! record)
 *   install_kbytes- installed size, i.e. ceil(sum over non-root entries of
 *                   roundup(st_size, 512) / 1024), as pkgbuild reports it
 *   plain_size    - sum of the non-root entries' st_size without the
 *                   512-byte block padding, the figure a component
 *                   package's installKBytes is derived from
 */
struct payload {
	unsigned char *data;
	size_t size;
	size_t uncompressed;
	int file_count;
	size_t install_kbytes;
	unsigned long long plain_size;
};

/*
 * Walk root, delegate the cpio(1) copy-out (-o -H odc) and gzip the result
 * with zlib. Returns 0 on success (-1 on failure), filling *out.
 *
 * preserve_owner selects the recorded uid/gid: 0 sanitizes ownership to
 * root/0 ("recommended", as a root Payload does), non-zero preserves the
 * source ownership (as the Scripts archive does).
 *
 * root_st, when non-NULL, supplies the metadata recorded for the walk root
 * (".") in place of lstat(root).  productbuild --component archives the
 * bundle's enclosing directory, so the "." record carries that directory's
 * mode/nlink/times rather than the temporary staging directory's.
 */
int payload_build(const char *root, struct payload *out, int preserve_owner,
    const struct stat *root_st);
int payload_stage(const char *root, char **stage_out, struct payload *out,
    int preserve_owner);

#endif /* PAYLOAD_H */
