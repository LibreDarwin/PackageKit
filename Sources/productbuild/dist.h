/*
 * Copyright (c) 2026 Sunneva N. Mariu <sunnevanattsol@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef DIST_H
#define DIST_H

#include <stddef.h>

struct bundle_components;

/*
 * Synthesize an installer-gui-script Distribution XML for a product
 * archive. This mirrors the XML that Apple's productbuild generates when
 * you don't pass --distribution.  `identifier` names the component and is
 * used for every pkg-ref/choice id; `pkg_file` is the archive member path
 * referenced by the final "#..." pkg-ref.
 *
 * When `bundles` is non-NULL the leading pkg-ref carries a populated
 * <bundle-version> block.  `title` (productbuild --component) additionally
 * emits <product>/<title> and per-choice title/versStr attributes;
 * `short_version` supplies the human-facing version for those.
 *
 * Returns a malloc'd string (caller frees); sets *out_len (excl. NUL).
 */
char *dist_synthesize(const char *identifier, const char *version,
    const char *short_version, const char *title,
    const char *pkg_file, const char *install_location,
    const struct bundle_components *bundles,
    size_t install_kbytes, const char *host_arch, size_t *out_len);

#endif /* DIST_H */
