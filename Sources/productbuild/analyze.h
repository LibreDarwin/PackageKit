/*
 * Copyright (c) 2026 Sunneva N. Mariu <sunnevanattsol@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef ANALYZE_H
#define ANALYZE_H

#include <stddef.h>

struct bundle_components;

/*
 * Build the pkg-info Document for the package. Mirrors the XML emitted by
 * `pkgbuild`: a <payload> record with numberOfFiles + installKBytes plus
 * the standard bundle/upgrade/atomic/strict/relocate elements.  When
 * `bundles` is non-NULL each bundle contributes a <bundle> element and the
 * corresponding group entries.
 * If scripts_dir is non-NULL and contains preinstall/postinstall scripts,
 * a <scripts> element is emitted listing them.
 * When content_mode is set (productbuild --content) the record carries
 * content-type="in-app" instead of install-location.  preserve_xattr adds
 * preserve-xattr="true" (productbuild --component).
 * Returns a malloc'd NUL-terminated string; sets *out_len (excl. NUL).
 */
char *pkginfo_build(const char *identifier, const char *version,
    const char *install_location, int content_mode, const char *scripts_dir,
    int number_of_files, size_t install_kbytes,
    const struct bundle_components *bundles, int preserve_xattr,
    size_t *out_len);

#endif /* ANALYZE_H */
