/*
 * analyze - PackageInfo XML construction.
 *
 * Copyright (c) 2026 Sunneva N. Mariu <sunnevanattsol@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <CoreFoundation/CoreFoundation.h>

#include "analyze.h"

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
sbraww(struct sb *b, const char *s, size_t n)
{
	sbneed(b, n);
	memcpy(b->p + b->n, s, n);
	b->n += n;
	b->p[b->n] = '\0';
}

static void
sbadd(struct sb *b, const char *s)
{
	sbraww(b, s, strlen(s));
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

static char *
cf2c(CFStringRef s)
{
	if (s == NULL)
		return NULL;
	CFIndex n = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s),
	    kCFStringEncodingUTF8) + 1;
	char *buf = malloc(n);
	if (buf == NULL)
		return NULL;
	if (!CFStringGetCString(s, buf, n, kCFStringEncodingUTF8)) {
		free(buf);
		return NULL;
	}
	return buf;
}

static void
attr_escape(struct sb *b, const char *s)
{
	for (; *s != '\0'; s++) {
		switch (*s) {
		case '&':
			sbadd(b, "&amp;");
			break;
		case '<':
			sbadd(b, "&lt;");
			break;
		case '>':
			sbadd(b, "&gt;");
			break;
		case '"':
			sbadd(b, "&quot;");
			break;
		default:
			sbraww(b, s, 1);
			break;
		}
	}
}

static void
sb_attr(struct sb *b, const char *name, const char *val)
{
	sbfmt(b, " %s=\"", name);
	attr_escape(b, val);
	sbadd(b, "\"");
}

/*
 * Emit the attribute string for a <bundle> in `pkgbuild` order: the
 * attributes live in a dictionary keyed ``id``, the two version keys and
 * ``path``; the serialization order is that dictionary's enumeration order.
 */
static char *
bundle_attrs(const struct bundle_component *c, int with_path)
{
	CFMutableDictionaryRef d = CFDictionaryCreateMutable(NULL, 0,
	    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (d == NULL)
		abort();

	CFStringRef v = CFStringCreateWithCString(NULL, c->identifier,
	    kCFStringEncodingUTF8);
	CFDictionarySetValue(d, CFSTR("id"), v);
	CFRelease(v);

	if (c->short_version != NULL) {
		v = CFStringCreateWithCString(NULL, c->short_version,
		    kCFStringEncodingUTF8);
		CFDictionarySetValue(d, CFSTR("CFBundleShortVersionString"), v);
		CFRelease(v);
	}
	if (c->version != NULL) {
		v = CFStringCreateWithCString(NULL, c->version,
		    kCFStringEncodingUTF8);
		CFDictionarySetValue(d, CFSTR("CFBundleVersion"), v);
		CFRelease(v);
	}
	if (with_path) {
		char *p = NULL;
		if (asprintf(&p, "./%s", c->path) < 0)
			abort();
		v = CFStringCreateWithCString(NULL, p, kCFStringEncodingUTF8);
		CFDictionarySetValue(d, CFSTR("path"), v);
		CFRelease(v);
		free(p);
	}

	CFIndex cnt = CFDictionaryGetCount(d);
	CFTypeRef *keys = malloc(sizeof(*keys) * (cnt ? (size_t)cnt : 1));
	CFTypeRef *vals = malloc(sizeof(*vals) * (cnt ? (size_t)cnt : 1));
	if (keys == NULL || vals == NULL)
		abort();
	CFDictionaryGetKeysAndValues(d, keys, vals);

	struct sb out = {0};
	for (CFIndex i = 0; i < cnt; i++) {
		char *kn = cf2c((CFStringRef)keys[i]);
		char *vn = cf2c((CFStringRef)vals[i]);
		sb_attr(&out, kn ? kn : "", vn ? vn : "");
		free(kn);
		free(vn);
	}
	CFRelease(d);
	free(keys);
	free(vals);
	if (out.p == NULL)
		out.p = strdup("");
	return out.p;
}

typedef int (*bpred)(const struct bundle_component *);

static void
sb_group(struct sb *b, const char *name, const struct bundle_components *bc,
    bpred pred)
{
	size_t i, n = 0;
	for (i = 0; bc != NULL && i < bc->n; i++)
		if (pred != NULL && pred(&bc->v[i]))
			n++;
	if (n == 0) {
		sbfmt(b, "    <%s/>\n", name);
		return;
	}
	sbfmt(b, "    <%s>\n", name);
	for (i = 0; bc != NULL && i < bc->n; i++) {
		if (pred == NULL || !pred(&bc->v[i]))
			continue;
		sbadd(b, "        <bundle id=\"");
		attr_escape(b, bc->v[i].identifier);
		sbadd(b, "\"/>\n");
	}
	sbfmt(b, "    </%s>\n", name);
}

static int pred_version(const struct bundle_component *c) { return c->version_checked; }
static int pred_upgrade(const struct bundle_component *c) { return c->overwrite_upgrade; }
static int pred_strict(const struct bundle_component *c) { return c->strict_identifier; }
static int pred_relocate(const struct bundle_component *c) { return c->relocatable; }

static void
generator_version(char *buf, size_t n)
{
	static const char ident[] = "pkgbuild-864.120.2";
	const char *dash = strrchr(ident, '-');
	double v = dash ? strtod(dash + 1, NULL) : 0.0;
	char osver[64] = "";
	size_t len = sizeof osver;
	if (sysctlbyname("kern.osversion", osver, &len, NULL, 0) != 0)
		osver[0] = '\0';
	snprintf(buf, n, "InstallCmds-%g (%s)", v, osver);
}

static int
collect_scripts(const char *scripts_dir, struct sb *b)
{
	if (scripts_dir == NULL)
		return 0;

	struct stat st;
	if (stat(scripts_dir, &st) != 0 || !S_ISDIR(st.st_mode))
		return 0;

	char path[PATH_MAX];
	int has_pre = 0, has_post = 0;

	if (snprintf(path, sizeof path, "%s/preinstall", scripts_dir) < (int)sizeof path &&
	    stat(path, &st) == 0 && S_ISREG(st.st_mode))
		has_pre = 1;
	if (snprintf(path, sizeof path, "%s/postinstall", scripts_dir) < (int)sizeof path &&
	    stat(path, &st) == 0 && S_ISREG(st.st_mode))
		has_post = 1;

	if (!has_pre && !has_post)
		return 0;

	sbadd(b, "    <scripts>\n");
	if (has_pre)
		sbadd(b, "        <preinstall file=\"./preinstall\" timeout=\"600\"/>\n");
	if (has_post)
		sbadd(b, "        <postinstall file=\"./postinstall\" timeout=\"600\"/>\n");
	sbadd(b, "    </scripts>\n");
	return 0;
}

char *
pkginfo_build(const char *identifier, const char *version,
    const char *install_location, const char *scripts_dir,
    int number_of_files, size_t install_kbytes,
    const struct bundle_components *bundles, size_t *out_len)
{
	char gen[128];
	generator_version(gen, sizeof gen);

	char loc_attr[512];
	if (install_location != NULL)
		snprintf(loc_attr, sizeof loc_attr,
		    " install-location=\"%s\"", install_location);
	else
		loc_attr[0] = '\0';

	struct sb b = {0};
	sbfmt(&b,
	    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
	    "<pkg-info overwrite-permissions=\"true\" relocatable=\"false\" "
	    "identifier=\"%s\" postinstall-action=\"none\" version=\"%s\" "
	    "format-version=\"2\" generator-version=\"%s\"%s auth=\"root\">\n"
	    "    <payload numberOfFiles=\"%d\" installKBytes=\"%zu\"/>\n",
	    identifier ? identifier : "com.apple.unknown",
	    version ? version : "1.0",
	    gen, loc_attr,
	    number_of_files > 0 ? number_of_files : 1,
	    install_kbytes);

	for (size_t i = 0; bundles != NULL && i < bundles->n; i++) {
		char *attrs = bundle_attrs(&bundles->v[i], 1);
		sbfmt(&b, "    <bundle%s/>\n", attrs);
		free(attrs);
	}

	sb_group(&b, "bundle-version", bundles, pred_version);
	sb_group(&b, "upgrade-bundle", bundles, pred_upgrade);
	sb_group(&b, "update-bundle", bundles, NULL);
	sb_group(&b, "atomic-update-bundle", bundles, NULL);
	sb_group(&b, "strict-identifier", bundles, pred_strict);
	sb_group(&b, "relocate", bundles, pred_relocate);

	collect_scripts(scripts_dir, &b);

	sbadd(&b, "</pkg-info>");

	if (b.p == NULL)
		b.p = strdup("");
	*out_len = b.n;
	return b.p;
}
