/*
 * Copyright (c) 2026 Sunneva N. Mariu <sunnevanattsol@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef HOSTARCH_H
#define HOSTARCH_H

/*
 * Return the host architectures of a bundle's main executable as a
 * comma-separated list (e.g. "arm64,x86_64"), or NULL when the bundle
 * has no readable Mach-O main executable.  The caller frees the result.
 *
 * Only the main executable counts: a bundle shipping helper tools for
 * other architectures still reports just its own executable's set.
 */
char *host_archs_for_bundle(const char *bundle_path);

#endif /* HOSTARCH_H */
