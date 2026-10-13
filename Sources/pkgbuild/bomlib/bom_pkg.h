/*
 * Copyright (c) 2026 Sunneva N. Mariu <sunnevanattsol@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef BOM_PKG_H
#define BOM_PKG_H

#include <stddef.h>

/*
 * Build the BOM that Apple's pkgbuild(1) embeds in a component package.
 * Walks root in readdir order, synthesises ._ AppleDouble sidecar path
 * records from extended attributes, and serialises a BOMStore image with
 * the same block layout, dense free-list allocator and commit protocol as
 * Apple's Bom.framework.  Returns a malloc'd buffer (caller frees) or NULL.
 */
unsigned char *bm_pkg_build(const char *root, size_t *out_len);

#endif /* BOM_PKG_H */
