/*
 * Copyright (c) 2026 Sunneva N. Mariu <sunnevanattsol@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef BUNDLES_H
#define BUNDLES_H

#include <stddef.h>

/*
 * Infer the bundle components under root and return the component property
 * list as XML (the format written by `pkgbuild --analyze`).  The returned
 * string is malloc'd and NUL-terminated; *out_len excludes the NUL.
 */
char *component_plist_for_root(const char *root, size_t *out_len);

struct bundle_component {
	char *path;
	char *identifier;
	char *short_version;
	char *version;
	int nested;
	int strict_identifier;
	int relocatable;
	int version_checked;
	int overwrite_upgrade;
};

struct bundle_components {
	struct bundle_component *v;
	size_t n;
};

/*
 * Collect the bundle components under root in component-map order (the order
 * `pkgbuild` reports "Adding component at" and writes <bundle> elements).
 * Returns NULL on allocation failure.
 */
struct bundle_components *bundles_for_root(const char *root);
void bundles_free(struct bundle_components *b);

/*
 * Return the title of the bundle at path: its CFBundleDisplayName, else
 * its CFBundleName, else NULL when the path is not a bundle.  The caller
 * frees the result.
 */
char *bundle_title_for_path(const char *path);

#endif /* BUNDLES_H */
