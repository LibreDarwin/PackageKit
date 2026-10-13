/*
 * bundles - infer bundle components from a package root.
 *
 * Copyright (c) 2026 Sunneva N. Mariu <sunnevanattsol@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <CoreFoundation/CoreFoundation.h>

#include "bundles.h"

struct comp {
	char *rel;
	int parent;
};

struct comps {
	struct comp *v;
	size_t n;
	size_t cap;
};

struct buf {
	char *p;
	size_t n;
	size_t cap;
};

static void
nomem(void)
{
	abort();
}

static void
bneed(struct buf *b, size_t extra)
{
	if (b->n + extra + 1 > b->cap) {
		size_t cap = b->cap ? b->cap : 256;
		while (cap < b->n + extra + 1)
			cap *= 2;
		b->p = realloc(b->p, cap);
		if (b->p == NULL)
			nomem();
		b->cap = cap;
	}
}

static void
bput(struct buf *b, const char *s, size_t n)
{
	bneed(b, n);
	memcpy(b->p + b->n, s, n);
	b->n += n;
	b->p[b->n] = '\0';
}

static void
bs(struct buf *b, const char *s)
{
	bput(b, s, strlen(s));
}

static void
bindent(struct buf *b, int depth)
{
	while (depth-- > 0)
		bput(b, "\t", 1);
}

static void
emit_str(struct buf *b, const char *s)
{
	bs(b, "<string>");
	for (; *s != '\0'; s++) {
		switch (*s) {
		case '&':
			bs(b, "&amp;");
			break;
		case '<':
			bs(b, "&lt;");
			break;
		case '>':
			bs(b, "&gt;");
			break;
		default:
			bput(b, s, 1);
			break;
		}
	}
	bs(b, "</string>");
}

static const char *
ext_of(const char *rel)
{
	const char *base = strrchr(rel, '/');
	const char *dot = strrchr(base ? base + 1 : rel, '.');
	if (dot == NULL || dot == (base ? base + 1 : rel) || dot[1] == '\0')
		return "";
	return dot + 1;
}

static int
is_bundle(const char *path)
{
	CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL,
	    (const UInt8 *)path, strlen(path), true);
	if (url == NULL)
		return 0;
	CFBundleRef bundle = CFBundleCreate(NULL, url);
	int ok = (bundle != NULL && CFBundleGetIdentifier(bundle) != NULL);
	if (bundle != NULL)
		CFRelease(bundle);
	CFRelease(url);
	return ok;
}

static void
resource_path(const char *dir, char *out, size_t n)
{
	char tmp[PATH_MAX];
	struct stat st;

	snprintf(tmp, sizeof tmp, "%s/Contents/Resources", dir);
	if (stat(tmp, &st) != 0)
		snprintf(tmp, sizeof tmp, "%s/Resources", dir);
	if (stat(tmp, &st) != 0) {
		if (realpath(dir, out) == NULL)
			snprintf(out, n, "%s", dir);
		return;
	}
	if (realpath(tmp, out) == NULL)
		snprintf(out, n, "%s", tmp);
}

static void
push(struct comps *cs, char *rel, int parent)
{
	if (cs->n == cs->cap) {
		cs->cap = cs->cap ? cs->cap * 2 : 16;
		cs->v = realloc(cs->v, cs->cap * sizeof *cs->v);
		if (cs->v == NULL)
			nomem();
	}
	cs->v[cs->n].rel = rel;
	cs->v[cs->n].parent = parent;
	cs->n++;
}

static void
walk(const char *root, const char *rel, int parent, struct comps *cs)
{
	char dir[PATH_MAX];
	DIR *d;
	struct dirent *e;

	if (rel[0])
		snprintf(dir, sizeof dir, "%s/%s", root, rel);
	else
		snprintf(dir, sizeof dir, "%s", root);

	d = opendir(dir);
	if (d == NULL)
		return;

	while ((e = readdir(d)) != NULL) {
		char full[PATH_MAX];
		char crel[PATH_MAX];
		struct stat st;

		if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
			continue;

		snprintf(full, sizeof full, "%s/%s", dir, e->d_name);
		if (lstat(full, &st) != 0)
			continue;
		if (S_ISLNK(st.st_mode))
			continue;

		if (rel[0])
			snprintf(crel, sizeof crel, "%s/%s", rel, e->d_name);
		else
			snprintf(crel, sizeof crel, "%s", e->d_name);

		if (is_bundle(full)) {
			if (parent >= 0 &&
			    strcmp(ext_of(cs->v[parent].rel), "framework") == 0) {
				char pabs[PATH_MAX];
				char ra[PATH_MAX];
				char rp[PATH_MAX];

				snprintf(pabs, sizeof pabs, "%s/%s", root,
				    cs->v[parent].rel);
				resource_path(full, ra, sizeof ra);
				resource_path(pabs, rp, sizeof rp);
				if (strcmp(ra, rp) == 0)
					continue;
			}
			push(cs, strdup(crel), parent);
			walk(root, crel, (int)(cs->n - 1), cs);
		} else {
			walk(root, crel, parent, cs);
		}
	}
	closedir(d);
}

static void emit_dict(struct buf *b, struct comps *cs, int idx, int depth);

static void
emit_children(struct buf *b, struct comps *cs, int idx, int depth)
{
	size_t i;

	bindent(b, depth);
	bs(b, "<array>\n");
	for (i = 0; i < cs->n; i++)
		if (cs->v[i].parent == idx)
			emit_dict(b, cs, (int)i, depth + 1);
	bindent(b, depth);
	bs(b, "</array>\n");
}

static void
emit_dict(struct buf *b, struct comps *cs, int idx, int depth)
{
	const char *rel = cs->v[idx].rel;
	const char *ext = ext_of(rel);
	int nested = cs->v[idx].parent >= 0;
	int is_app = strcmp(ext, "app") == 0;
	int is_wdgt = strcmp(ext, "wdgt") == 0;
	int has_child = 0;
	size_t i;

	for (i = 0; i < cs->n; i++)
		if (cs->v[i].parent == idx) {
			has_child = 1;
			break;
		}

	bindent(b, depth);
	bs(b, "<dict>\n");

	if (is_app || is_wdgt) {
		bindent(b, depth + 1);
		bs(b, "<key>BundleHasStrictIdentifier</key>\n");
		bindent(b, depth + 1);
		bs(b, "<true/>\n");
	}
	if (!nested && is_app) {
		bindent(b, depth + 1);
		bs(b, "<key>BundleIsRelocatable</key>\n");
		bindent(b, depth + 1);
		bs(b, "<true/>\n");
	}
	if (!nested) {
		bindent(b, depth + 1);
		bs(b, "<key>BundleIsVersionChecked</key>\n");
		bindent(b, depth + 1);
		bs(b, "<true/>\n");
	}

	bindent(b, depth + 1);
	bs(b, "<key>BundleOverwriteAction</key>\n");
	bindent(b, depth + 1);
	bs(b, nested ? "<string></string>\n" : "<string>upgrade</string>\n");

	if (has_child) {
		bindent(b, depth + 1);
		bs(b, "<key>ChildBundles</key>\n");
		emit_children(b, cs, idx, depth + 1);
	}

	bindent(b, depth + 1);
	bs(b, "<key>RootRelativeBundlePath</key>\n");
	bindent(b, depth + 1);
	emit_str(b, rel);
	bs(b, "\n");

	bindent(b, depth);
	bs(b, "</dict>\n");
}

struct mcomp {
	char *rel;
	int parent;
	char *identifier;
	char *short_version;
	char *version;
};

struct mcomps {
	struct mcomp *v;
	size_t n;
	size_t cap;
};

static char *
cfstrdup(CFStringRef s)
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

static char *
cfdict_string(CFBundleRef bundle, CFStringRef key)
{
	return cfstrdup((CFStringRef)CFBundleGetValueForInfoDictionaryKey(bundle,
	    key));
}

static struct mcomp *
mpush(struct mcomps *cs, const char *rel, int parent)
{
	if (cs->n == cs->cap) {
		cs->cap = cs->cap ? cs->cap * 2 : 16;
		cs->v = realloc(cs->v, cs->cap * sizeof *cs->v);
		if (cs->v == NULL)
			nomem();
	}
	struct mcomp *m = &cs->v[cs->n++];
	m->rel = strdup(rel);
	m->parent = parent;
	m->identifier = NULL;
	m->short_version = NULL;
	m->version = NULL;
	return m;
}

static void
walk_meta(const char *root, const char *rel, int parent, struct mcomps *cs)
{
	char dir[PATH_MAX];
	DIR *d;
	struct dirent *e;

	if (rel[0])
		snprintf(dir, sizeof dir, "%s/%s", root, rel);
	else
		snprintf(dir, sizeof dir, "%s", root);

	d = opendir(dir);
	if (d == NULL)
		return;

	while ((e = readdir(d)) != NULL) {
		char full[PATH_MAX];
		char crel[PATH_MAX];
		struct stat st;

		if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
			continue;

		snprintf(full, sizeof full, "%s/%s", dir, e->d_name);
		if (lstat(full, &st) != 0 || S_ISLNK(st.st_mode))
			continue;

		if (rel[0])
			snprintf(crel, sizeof crel, "%s/%s", rel, e->d_name);
		else
			snprintf(crel, sizeof crel, "%s", e->d_name);

		if (is_bundle(full)) {
			if (parent >= 0 &&
			    strcmp(ext_of(cs->v[parent].rel), "framework") == 0) {
				char pabs[PATH_MAX];
				char ra[PATH_MAX];
				char rp[PATH_MAX];

				snprintf(pabs, sizeof pabs, "%s/%s", root,
				    cs->v[parent].rel);
				resource_path(full, ra, sizeof ra);
				resource_path(pabs, rp, sizeof rp);
				if (strcmp(ra, rp) == 0)
					continue;
			}

			CFURLRef url = CFURLCreateFromFileSystemRepresentation(
			    NULL, (const UInt8 *)full, strlen(full), true);
			CFBundleRef bundle = url ? CFBundleCreate(NULL, url) : NULL;
			struct mcomp *m = mpush(cs, crel, parent);
			if (bundle != NULL) {
				m->identifier = cfstrdup(CFBundleGetIdentifier(bundle));
				m->short_version = cfdict_string(bundle,
				    CFSTR("CFBundleShortVersionString"));
				m->version = cfdict_string(bundle,
				    CFSTR("CFBundleVersion"));
				CFRelease(bundle);
			}
			if (url != NULL)
				CFRelease(url);

			walk_meta(root, crel, (int)(cs->n - 1), cs);
		} else {
			walk_meta(root, crel, parent, cs);
		}
	}
	closedir(d);
}

struct bundle_components *
bundles_for_root(const char *root)
{
	struct mcomps cs = {0};
	size_t i;

	walk_meta(root, "", -1, &cs);

	struct bundle_components *out = calloc(1, sizeof *out);
	if (out == NULL)
		nomem();
	out->v = calloc(cs.n ? cs.n : 1, sizeof *out->v);
	if (out->v == NULL)
		nomem();

	CFMutableDictionaryRef map = CFDictionaryCreateMutable(NULL, 0,
	    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (map == NULL)
		nomem();

	for (i = 0; i < cs.n; i++) {
		CFStringRef key = CFStringCreateWithCString(NULL, cs.v[i].rel,
		    kCFStringEncodingUTF8);
		CFNumberRef num = CFNumberCreate(NULL, kCFNumberCFIndexType,
		    &i);
		CFDictionarySetValue(map, key, num);
		CFRelease(num);
		CFRelease(key);
	}

	CFIndex cnt = CFDictionaryGetCount(map);
	CFTypeRef *keys = malloc(sizeof(*keys) * (cnt ? (size_t)cnt : 1));
	CFTypeRef *vals = malloc(sizeof(*vals) * (cnt ? (size_t)cnt : 1));
	if (keys == NULL || vals == NULL)
		nomem();
	CFDictionaryGetKeysAndValues(map, keys, vals);

	for (CFIndex k = 0; k < cnt; k++) {
		CFIndex idx = 0;
		CFNumberGetValue((CFNumberRef)vals[k], kCFNumberCFIndexType,
		    &idx);
		struct mcomp *m = &cs.v[idx];
		const char *ext = ext_of(m->rel);
		int nested = m->parent >= 0;

		struct bundle_component *b = &out->v[k];
		b->path = m->rel;
		b->identifier = m->identifier ? m->identifier : strdup("");
		b->short_version = m->short_version;
		b->version = m->version;
		b->nested = nested;
		b->strict_identifier = (strcmp(ext, "app") == 0 ||
		    strcmp(ext, "wdgt") == 0);
		b->relocatable = (!nested && strcmp(ext, "app") == 0);
		b->version_checked = !nested;
		b->overwrite_upgrade = !nested;

		m->rel = NULL;
		m->identifier = NULL;
		m->short_version = NULL;
		m->version = NULL;
	}
	out->n = (size_t)cnt;

	CFRelease(map);
	free(keys);
	free(vals);

	for (i = 0; i < cs.n; i++) {
		free(cs.v[i].rel);
		free(cs.v[i].identifier);
		free(cs.v[i].short_version);
		free(cs.v[i].version);
	}
	free(cs.v);
	return out;
}

void
bundles_free(struct bundle_components *b)
{
	if (b == NULL)
		return;
	for (size_t i = 0; i < b->n; i++) {
		free(b->v[i].path);
		free(b->v[i].identifier);
		free(b->v[i].short_version);
		free(b->v[i].version);
	}
	free(b->v);
	free(b);
}

char *
component_plist_for_root(const char *root, size_t *out_len)
{
	struct comps cs = {0};
	struct buf b = {0};
	size_t i;

	walk(root, "", -1, &cs);

	bs(&b, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	bs(&b, "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
	    "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
	bs(&b, "<plist version=\"1.0\">\n");

	if (cs.n == 0) {
		bs(&b, "<array/>\n");
	} else {
		bs(&b, "<array>\n");
		for (i = 0; i < cs.n; i++)
			if (cs.v[i].parent < 0)
				emit_dict(&b, &cs, (int)i, 1);
		bs(&b, "</array>\n");
	}
	bs(&b, "</plist>\n");

	for (i = 0; i < cs.n; i++)
		free(cs.v[i].rel);
	free(cs.v);

	*out_len = b.n;
	return b.p;
}
