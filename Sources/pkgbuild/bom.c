/*
 * bom - generate a Bill Of Materials for a source root.
 *
 * Copyright (c) 2026 Sunneva N. Mariu <sunnevanattsol@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdlib.h>

#include "bom.h"
#include "bomlib/bom_pkg.h"

unsigned char *
bom_build(const char *root, size_t *out_len, int component_mode)
{
	return bm_pkg_build(root, out_len, component_mode);
}
