/*
 * dist - synthesize an installer-gui-script Distribution XML.
 *
 * Copyright (c) 2026 Sunneva N. Mariu <sunnevanattsol@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Mirrors the Distribution file that Apple's productbuild writes when
 * invoked with --root (or --component / --content), synthesizing a
 * distribution from the single component package.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "dist.h"
#include "bundles.h"

struct sb {
	char *p;
	size_t n;
	size_t cap;
};

static void
sbneed(struct sb *b, size_t extra)
{
	if (b->n + extra + 1 > b->cap) {
		size_t cap = b->cap ? b->cap : 256;
		while (cap < b->n + extra + 1)
			cap *= 2;
		b->p = realloc(b->p, cap);
		if (b->p == NULL)
			abort();
		b->cap = cap;
	}
}

static void
sbadd(struct sb *b, const char *s)
{
	size_t n = strlen(s);
	sbneed(b, n);
	memcpy(b->p + b->n, s, n);
	b->n += n;
	b->p[b->n] = '\0';
}

static void
sbfmt(struct sb *b, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char *tmp = NULL;
	if (vasprintf(&tmp, fmt, ap) < 0)
		abort();
	va_end(ap);
	sbadd(b, tmp);
	free(tmp);
}

/* XML attribute escaping for &, <, > and ". */
static void
xesc(struct sb *b, const char *s)
{
	for (; s != NULL && *s != '\0'; s++) {
		switch (*s) {
		case '&': sbadd(b, "&amp;"); break;
		case '<': sbadd(b, "&lt;"); break;
		case '>': sbadd(b, "&gt;"); break;
		case '"': sbadd(b, "&quot;"); break;
		default:
			sbneed(b, 1);
			b->p[b->n++] = *s;
			b->p[b->n] = '\0';
			break;
		}
	}
}

char *
dist_synthesize(const char *identifier, const char *version,
    const char *short_version, const char *title,
    const char *pkg_file, const char *install_location,
    const struct bundle_components *bundles,
    size_t install_kbytes, const char *host_arch, size_t *out_len)
{
	if (identifier == NULL)
		identifier = "com.apple.unknown";
	if (version == NULL)
		version = "0";
	if (pkg_file == NULL)
		pkg_file = "root.pkg";
	if (host_arch == NULL || *host_arch == '\0')
		host_arch = "x86_64,arm64";

	const char *sv = short_version ? short_version : version;

	struct sb b = {0};
	sbadd(&b, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
	sbadd(&b, "<installer-gui-script minSpecVersion=\"1\">\n");

	/* Leading pkg-ref: empty <bundle-version/> for plain roots, a
	 * populated block when the component has bundle(s). */
	sbadd(&b, "    <pkg-ref id=\"");
	xesc(&b, identifier);
	sbadd(&b, "\">\n");
	if (bundles != NULL && bundles->n > 0) {
		sbadd(&b, "        <bundle-version>\n");
		for (size_t i = 0; i < bundles->n; i++) {
			const struct bundle_component *c = &bundles->v[i];
			sbadd(&b, "            <bundle");
			if (c->short_version != NULL) {
				sbadd(&b, " CFBundleShortVersionString=\"");
				xesc(&b, c->short_version);
				sbadd(&b, "\"");
			}
			if (c->version != NULL) {
				sbadd(&b, " CFBundleVersion=\"");
				xesc(&b, c->version);
				sbadd(&b, "\"");
			}
			sbadd(&b, " id=\"");
			xesc(&b, c->identifier);
			sbadd(&b, "\" path=\"");
			xesc(&b, c->path);
			sbadd(&b, "\"/>\n");
		}
		sbadd(&b, "        </bundle-version>\n");
	} else {
		sbadd(&b, "        <bundle-version/>\n");
	}
	sbadd(&b, "    </pkg-ref>\n");

	if (title != NULL) {
		sbadd(&b, "    <product id=\"");
		xesc(&b, identifier);
		sbadd(&b, "\" version=\"");
		xesc(&b, sv);
		sbadd(&b, "\"/>\n    <title>");
		xesc(&b, title);
		sbadd(&b, "</title>\n");
	}

	sbfmt(&b, "    <options customize=\"never\" require-scripts=\"false\" "
	    "hostArchitectures=\"%s\"/>\n", host_arch);

	sbadd(&b, "    <choices-outline>\n        <line choice=\"default\">\n"
	    "            <line choice=\"");
	xesc(&b, identifier);
	sbadd(&b, "\"/>\n        </line>\n    </choices-outline>\n");

	sbadd(&b, "    <choice id=\"default\"");
	if (title != NULL) {
		sbadd(&b, " title=\"");
		xesc(&b, title);
		sbadd(&b, "\" versStr=\"");
		xesc(&b, sv);
		sbadd(&b, "\"");
	}
	sbadd(&b, "/>\n");

	sbadd(&b, "    <choice id=\"");
	xesc(&b, identifier);
	sbadd(&b, "\"");
	if (title != NULL) {
		sbadd(&b, " title=\"");
		xesc(&b, title);
		sbadd(&b, "\"");
	}
	sbadd(&b, " visible=\"false\"");
	/* customLocation is emitted only for a non-root install path;
	 * installing at "/" needs none. */
	if (install_location != NULL && strcmp(install_location, "/") != 0) {
		sbadd(&b, " customLocation=\"");
		xesc(&b, install_location);
		sbadd(&b, "\"");
	}
	sbadd(&b, ">\n        <pkg-ref id=\"");
	xesc(&b, identifier);
	sbadd(&b, "\"/>\n    </choice>\n");

	sbadd(&b, "    <pkg-ref id=\"");
	xesc(&b, identifier);
	sbadd(&b, "\" version=\"");
	xesc(&b, version);
	sbfmt(&b, "\" onConclusion=\"none\" installKBytes=\"%zu\" "
	    "updateKBytes=\"0\">#", install_kbytes);
	xesc(&b, pkg_file);
	sbadd(&b, "</pkg-ref>\n</installer-gui-script>");

	if (b.p == NULL)
		b.p = strdup("");
	*out_len = b.n;
	return b.p;
}
