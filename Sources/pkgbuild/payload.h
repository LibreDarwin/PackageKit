/*
 * Copyright (c) 2026 Sunneva N. Mariu <sunnevanattsol@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <stddef.h>
#include <stdint.h>

/*
 * Generated from a source root directory.
 *   data         - gzip( cpio -o -H odc ) for the root's files
 *   size          - byte length of data
 *   uncompressed  - byte length of the raw cpio
 *   file_count    - number of cpio records (dirs + files + AppleDouble
 *                   sidecars, incl. "." but excluding the TRAILER!!! record)
 *   install_kbytes- installed size, i.e. ceil(sum over non-root entries of
 *                   roundup(st_size, 512) / 1024), as pkgbuild reports it
 */
struct payload {
	unsigned char *data;
	size_t size;
	size_t uncompressed;
	int file_count;
	size_t install_kbytes;
};

/*
 * Walk root, delegate the cpio(1) copy-out (-o -H odc) and gzip the result
 * with zlib. Returns 0 on success (-1 on failure), filling *out.
 */
int payload_build(const char *root, struct payload *out);
int payload_stage(const char *root, char **stage_out, struct payload *out);

#endif /* PAYLOAD_H */
