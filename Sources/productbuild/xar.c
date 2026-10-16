/*
 * xar - minimal xar(1) archive builder/reader for productbuild.
 *
 * Copyright (c) 2026 Sunneva N. Mariu <sunnevanattsol@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Produces pkgutil-valid product archives.  Unlike pkgbuild's flat xar,
 * a product is a tree: a top-level Distribution file plus one directory
 * (e.g. root.pkg) per component package holding Bom/Payload/PackageInfo.
 * The header layout and heap-relative <offset> scheme reproduce a real
 * productbuild archive:
 *
 *   [28-byte header] [toc_z] [sha1(toc_z)] [entry data...]
 *
 * Differences from pkgbuild's writer, all verified against /usr/bin/
 * productbuild: zlib level 9, data precedes ea in the heap, ids follow a
 * depth-first pre-order, top-level <file>s are listed in reverse while a
 * directory's children are listed forward, nested files repeat their
 * <name>, and directories carry a synthetic all-zero attribute block.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <zlib.h>
#include <CommonCrypto/CommonDigest.h>

#include "xar.h"

/* --- growable text buffer (for TOC construction) --- */

struct sbuf {
	unsigned char *buf;
	size_t len;
	size_t cap;
};

static int
sbuf_init(struct sbuf *s)
{
	s->buf = NULL;
	s->len = 0;
	s->cap = 0;
	return 0;
}

static int
sbuf_cat(struct sbuf *s, const void *in, size_t n)
{
	if (s->len + n + 1 > s->cap) {
		size_t cap = s->cap ? s->cap : 512;
		while (cap < s->len + n + 1)
			cap *= 2;
		unsigned char *nd = realloc(s->buf, cap);
		if (nd == NULL)
			return -1;
		s->buf = nd;
		s->cap = cap;
	}
	memcpy(s->buf + s->len, in, n);
	s->len += n;
	s->buf[s->len] = '\0';
	return 0;
}

static int
sbuf_printf(struct sbuf *s, const char *fmt, ...)
{
	va_list ap;
	char *tmp;
	int r;
	va_start(ap, fmt);
	r = vasprintf(&tmp, fmt, ap);
	va_end(ap);
	if (r < 0)
		return -1;
	int rc = sbuf_cat(s, tmp, (size_t)r);
	free(tmp);
	return rc;
}

static void
sbuf_free(struct sbuf *s)
{
	free(s->buf);
	s->buf = NULL;
	s->len = 0;
	s->cap = 0;
}

/* A run of spaces; indentation is emitted with "%.*s" and a width. */
static const char spaces[] =
    "                                                                ";

/* --- big-endian writers --- */

static void
put_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)(v);
}

static void
put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)(v);
}

static uint32_t
get_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	    ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* --- compression + checksum helpers --- */

static int
zlib_compress(const void *in, size_t n, unsigned char **out, size_t *out_len)
{
	uLong bound = compressBound((uLong)n);
	unsigned char *buf = malloc(bound);
	if (buf == NULL)
		return -1;
	uLongf blen = bound;
	int rc = compress2(buf, &blen, (const Bytef *)in, (uLong)n,
	    Z_BEST_COMPRESSION);	/* productbuild uses level 9 */
	if (rc != Z_OK) {
		free(buf);
		return -1;
	}
	*out = buf;
	*out_len = (size_t)blen;
	return 0;
}

static void
sha1_hex(const void *data, size_t len, char out[41])
{
	unsigned char digest[20];
	CC_SHA1(data, (CC_LONG)len, digest);
	static const char hex[] = "0123456789abcdef";
	for (int i = 0; i < 20; i++) {
		out[i * 2] = hex[digest[i] >> 4];
		out[i * 2 + 1] = hex[digest[i] & 0xf];
	}
	out[40] = '\0';
}

/* ISO-8601 UTC timestamp; the archive <creation-time> omits the trailing Z
 * while the per-file ctime/mtime/atime include it, matching productbuild. */
static void
iso_time(time_t t, int with_z, char *out, size_t n)
{
	struct tm tm;
	gmtime_r(&t, &tm);
	strftime(out, n, with_z ? "%Y-%m-%dT%H:%M:%SZ" : "%Y-%m-%dT%H:%M:%S",
	    &tm);
}

/* --- on-disk metadata --- */

int
xar_entry_set_data_file(struct xar_entry *e, const void *data, size_t len)
{
	const char *dir = getenv("TMPDIR");
	char path[PATH_MAX];
	char names[1024];
	int fd;
	struct stat st;
	ssize_t nl;

	e->data = data;
	e->size = len;
	e->has_attr = 0;
	e->nxattr = 0;

	/*
	 * Create the file in $TMPDIR, as productbuild does.  On macOS a new
	 * file inherits its directory's group, so /tmp would yield group
	 * wheel (gid 0) while the per-user TMPDIR yields the user's own
	 * group (staff, gid 20), which is what shows up in the TOC.
	 */
	if (dir == NULL || *dir == '\0')
		dir = "/tmp/";
	snprintf(path, sizeof path, "%s%s.pkgbuild-XXXXXX", dir,
	    dir[strlen(dir) - 1] == '/' ? "" : "/");
	fd = mkstemp(path);
	if (fd < 0)
		return -1;
	if (len > 0 && write(fd, data, len) != (ssize_t)len) {
		close(fd);
		unlink(path);
		return -1;
	}
	fchmod(fd, 0644);
	close(fd);

	if (lstat(path, &st) != 0) {
		unlink(path);
		return -1;
	}

	e->has_attr = 1;
	e->mode = (uint32_t)st.st_mode;
	e->uid = (uint32_t)st.st_uid;
	e->gid = (uint32_t)st.st_gid;
	e->dev = (uint64_t)st.st_dev;
	e->ino = (uint64_t)st.st_ino;
	e->ctime = (uint32_t)st.st_ctime;
	e->mtime = (uint32_t)st.st_mtime;
	e->atime = (uint32_t)st.st_atime;
	e->birthtime = (uint32_t)st.st_birthtime;
	{
		struct passwd *pw = getpwuid(st.st_uid);
		struct group *gr = getgrgid(st.st_gid);
		snprintf(e->user, sizeof e->user, "%s",
		    pw ? pw->pw_name : "root");
		snprintf(e->group, sizeof e->group, "%s",
		    gr ? gr->gr_name : "wheel");
	}

	/* Extended attributes, notably com.apple.provenance which macOS
	 * stamps onto files created by this process. */
	nl = listxattr(path, names, sizeof names, XATTR_NOFOLLOW);
	if (nl > 0) {
		char *np = names;
		while (np < names + nl &&
		    e->nxattr < (int)(sizeof e->xattrs / sizeof e->xattrs[0])) {
			size_t nn = strlen(np);
			ssize_t vl = getxattr(path, np, NULL, 0, 0,
			    XATTR_NOFOLLOW);
			if (vl >= 0) {
				unsigned char *val = malloc((size_t)vl + 1);
				char *copy = strdup(np);
				if (val != NULL && copy != NULL &&
				    getxattr(path, np, val, (size_t)vl, 0,
				    XATTR_NOFOLLOW) == vl) {
					e->xattrs[e->nxattr].name = copy;
					e->xattrs[e->nxattr].value = val;
					e->xattrs[e->nxattr].vlen = (size_t)vl;
					e->nxattr++;
				} else {
					free(val);
					free(copy);
				}
			}
			np += nn + 1;
		}
	}

	unlink(path);
	return 0;
}

void
xar_entry_free_meta(struct xar_entry *e)
{
	for (int k = 0; k < e->nxattr; k++) {
		free((void *)e->xattrs[k].name);
		free((void *)e->xattrs[k].value);
	}
	e->nxattr = 0;
}

/* --- public API --- */

/* A heap blob: stored bytes plus the offsets/checksums the TOC needs. */
struct blob {
	unsigned char *p;	/* stored bytes (compressed or raw) */
	size_t len;		/* stored length */
	size_t usize;		/* uncompressed length */
	size_t off;		/* heap-relative offset of stored bytes */
	char ext[41];		/* sha1 of the uncompressed bytes */
	char arc[41];		/* sha1 of the stored bytes */
};

static int
comp_blob(struct blob *b, const void *data, size_t len, int compressed)
{
	b->usize = len;
	if (compressed) {
		if (zlib_compress(data, len, &b->p, &b->len) != 0)
			return -1;
	} else {
		b->p = malloc(len ? len : 1);
		if (b->p == NULL)
			return -1;
		memcpy(b->p, data, len);
		b->len = len;
	}
	sha1_hex(data, len, b->ext);
	sha1_hex(b->p, b->len, b->arc);
	return 0;
}

/* Emit the <data>/<ea> body.  productbuild orders the fields as
 * length,offset,size,encoding when the blob is compressed and
 * length,encoding,offset,size when it is stored. */
static int
emit_data(struct sbuf *s, int ind, const struct blob *b, const char *enc,
    int compressed)
{
	if (sbuf_printf(s, "%.*s<length>%zu</length>\n", ind, spaces,
	    b->len) != 0)
		return -1;
	if (compressed) {
		if (sbuf_printf(s, "%.*s<offset>%zu</offset>\n"
		    "%.*s<size>%zu</size>\n%.*s<encoding style=\"%s\"/>\n",
		    ind, spaces, b->off, ind, spaces, b->usize, ind, spaces,
		    enc) != 0)
			return -1;
	} else {
		if (sbuf_printf(s, "%.*s<encoding style=\"%s\"/>\n"
		    "%.*s<offset>%zu</offset>\n%.*s<size>%zu</size>\n",
		    ind, spaces, enc, ind, spaces, b->off, ind, spaces,
		    b->usize) != 0)
			return -1;
	}
	if (sbuf_printf(s, "%.*s<extracted-checksum style=\"sha1\">%s"
	    "</extracted-checksum>\n", ind, spaces, b->ext) != 0)
		return -1;
	if (sbuf_printf(s, "%.*s<archived-checksum style=\"sha1\">%s"
	    "</archived-checksum>\n", ind, spaces, b->arc) != 0)
		return -1;
	return 0;
}

/* Emit one <file> element.  Directories are left open (no closing tag) so
 * the caller can emit their children; files are self-contained. */
static int
emit_entry(struct sbuf *s, const struct xar_entry *e, const struct blob *d,
    const struct blob *ea, int eabase, int id, int depth, int nested)
{
	int e0 = 2 + depth;	/* indent of the <file> element */

	if (sbuf_printf(s, "%.*s<file id=\"%d\">\n", e0, spaces, id) != 0)
		return -1;

	if (!e->is_dir) {
		if (sbuf_printf(s, "%.*s<data>\n", e0 + 1, spaces) != 0)
			return -1;
		if (emit_data(s, e0 + 2, d, e->encoding, e->compressed) != 0)
			return -1;
		if (sbuf_printf(s, "%.*s</data>\n", e0 + 1, spaces) != 0)
			return -1;
		for (int k = 0; k < e->nxattr; k++) {
			if (sbuf_printf(s, "%.*s<ea id=\"%d\">\n", e0 + 1,
			    spaces, k) != 0)
				return -1;
			if (emit_data(s, e0 + 2, &ea[eabase + k], e->encoding,
			    e->compressed) != 0)
				return -1;
			if (sbuf_printf(s, "%.*s<name>%s</name>\n%.*s</ea>\n",
			    e0 + 2, spaces, e->xattrs[k].name, e0 + 1,
			    spaces) != 0)
				return -1;
		}
	}

	if (e->has_attr || e->is_dir) {
		if (e->has_attr && !e->is_dir) {
			struct tm bt;
			time_t btime = (time_t)e->birthtime;
			gmtime_r(&btime, &bt);
			if (sbuf_printf(s,
			    "%.*s<FinderCreateTime>\n"
			    "%.*s<nanoseconds>0</nanoseconds>\n"
			    "%.*s<time>1900-01-00T%02d:%02d:%02d</time>\n"
			    "%.*s</FinderCreateTime>\n",
			    e0 + 1, spaces, e0 + 2, spaces, e0 + 2, spaces,
			    bt.tm_hour, bt.tm_min, bt.tm_sec, e0 + 1,
			    spaces) != 0)
				return -1;
		}
		char c[32], m[32], a[32];
		iso_time((time_t)e->ctime, 1, c, sizeof c);
		iso_time((time_t)e->mtime, 1, m, sizeof m);
		iso_time((time_t)e->atime, 1, a, sizeof a);
		if (sbuf_printf(s,
		    "%.*s<ctime>%s</ctime>\n"
		    "%.*s<mtime>%s</mtime>\n"
		    "%.*s<atime>%s</atime>\n"
		    "%.*s<group>%s</group>\n"
		    "%.*s<gid>%u</gid>\n"
		    "%.*s<user>%s</user>\n"
		    "%.*s<uid>%u</uid>\n"
		    "%.*s<mode>%04o</mode>\n"
		    "%.*s<deviceno>%llu</deviceno>\n"
		    "%.*s<inode>%llu</inode>\n",
		    e0 + 1, spaces, c, e0 + 1, spaces, m, e0 + 1, spaces, a,
		    e0 + 1, spaces, e->group, e0 + 1, spaces, e->gid,
		    e0 + 1, spaces, e->user, e0 + 1, spaces, e->uid,
		    e0 + 1, spaces, (unsigned)(e->mode & 07777u),
		    e0 + 1, spaces, (unsigned long long)e->dev,
		    e0 + 1, spaces, (unsigned long long)e->ino) != 0)
			return -1;
	}

	if (sbuf_printf(s, "%.*s<type>%s</type>\n", e0 + 1, spaces,
	    e->is_dir ? "directory" : "file") != 0)
		return -1;
	if (sbuf_printf(s, "%.*s<name>%s</name>\n", e0 + 1, spaces,
	    e->name) != 0)
		return -1;
	/* A nested file repeats its name; top-level files and directories
	 * do not. */
	if (nested && !e->is_dir) {
		if (sbuf_printf(s, "%.*s<name>%s</name>\n", e0 + 1, spaces,
		    e->name) != 0)
			return -1;
	}
	if (!e->is_dir) {
		if (sbuf_printf(s, "%.*s</file>\n", e0, spaces) != 0)
			return -1;
	}
	return 0;
}

unsigned char *
xar_build(const struct xar_entry *entries, int n, size_t *out_len)
{
	struct blob *data = NULL, *ea = NULL;
	int *eabase = NULL;
	int *depth = NULL;
	unsigned char *toc_z = NULL;
	unsigned char *arch = NULL;
	struct sbuf toc;
	size_t toc_z_len = 0;
	size_t heap_off;
	int total_ea = 0, ei = 0, rc = -1;

	*out_len = 0;
	if (n < 1)
		return NULL;

	for (int i = 0; i < n; i++)
		total_ea += entries[i].nxattr;

	data = calloc((size_t)n, sizeof(*data));
	eabase = calloc((size_t)n, sizeof(*eabase));
	depth = calloc((size_t)n, sizeof(*depth));
	ea = calloc((size_t)(total_ea ? total_ea : 1), sizeof(*ea));
	if (data == NULL || eabase == NULL || depth == NULL || ea == NULL)
		goto out;

	/* Nesting depth from the parent links (parents precede children). */
	for (int i = 0; i < n; i++) {
		int p = entries[i].parent;
		depth[i] = (p >= 0 && p < i) ? depth[p] + 1 : 0;
	}

	for (int i = 0; i < n; i++) {
		const struct xar_entry *e = &entries[i];
		if (e->is_dir) {
			eabase[i] = ei;
			continue;
		}
		if (comp_blob(&data[i], e->data, e->size, e->compressed) != 0)
			goto out;
		eabase[i] = ei;
		for (int k = 0; k < e->nxattr; k++) {
			if (comp_blob(&ea[ei], e->xattrs[k].value,
			    e->xattrs[k].vlen, e->compressed) != 0)
				goto out;
			ei++;
		}
	}
	/* Each entry's data precedes its xattrs in the heap; entries are laid
	 * out in id order. */
	heap_off = 20;		/* 20-byte sha1(toc_z) checksum lives first */
	for (int i = 0; i < n; i++) {
		if (entries[i].is_dir)
			continue;
		data[i].off = heap_off;
		heap_off += data[i].len;
		for (int k = 0; k < entries[i].nxattr; k++) {
			ea[eabase[i] + k].off = heap_off;
			heap_off += ea[eabase[i] + k].len;
		}
	}

	sbuf_init(&toc);
	{
		char ct[32];
		iso_time(time(NULL), 0, ct, sizeof ct);
		if (sbuf_printf(&toc,
		    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		    "<xar>\n"
		    " <toc>\n"
		    "  <creation-time>%s</creation-time>\n"
		    "  <checksum style=\"sha1\">\n"
		    "   <offset>0</offset>\n"
		    "   <size>20</size>\n"
		    "  </checksum>\n", ct) != 0)
			goto out_sbuf;
	}
	/* Top-level entries are listed in reverse; each directory's children
	 * are listed forward. */
	for (int idx = n - 1; idx >= 0; idx--) {
		if (entries[idx].parent != -1)
			continue;
		if (emit_entry(&toc, &entries[idx], &data[idx], ea,
		    eabase[idx], idx + 1, depth[idx], 0) != 0)
			goto out_sbuf;
		if (entries[idx].is_dir) {
			for (int j = 0; j < n; j++) {
				if (entries[j].parent != idx)
					continue;
				if (emit_entry(&toc, &entries[j], &data[j], ea,
				    eabase[j], j + 1, depth[j], 1) != 0)
					goto out_sbuf;
			}
			if (sbuf_printf(&toc, "%.*s</file>\n", 2 + depth[idx],
			    spaces) != 0)
				goto out_sbuf;
		}
	}
	if (sbuf_cat(&toc, " </toc>\n</xar>\n",
	    strlen(" </toc>\n</xar>\n")) != 0)
		goto out_sbuf;

	/* Compress the TOC; the archive checksum is sha1 of the compressed TOC. */
	if (zlib_compress(toc.buf, toc.len, &toc_z, &toc_z_len) != 0)
		goto out_sbuf;

	unsigned char chk[20];
	CC_SHA1(toc_z, (CC_LONG)toc_z_len, chk);

	size_t heap_start = 28 + toc_z_len;
	size_t arch_len = heap_start + heap_off;
	arch = malloc(arch_len);
	if (arch == NULL)
		goto out_sbuf;

	uint32_t toclen_u = (uint32_t)toc.len;
	uint32_t toczlen_u = (uint32_t)toc_z_len;
	size_t p = 0;
	memcpy(arch + p, "xar!", 4); p += 4;
	put_be16(arch + p, 28); p += 2;		/* header_size */
	put_be16(arch + p, 1); p += 2;		/* version */
	put_be32(arch + p, 0); p += 4;		/* ? */
	put_be32(arch + p, toczlen_u); p += 4;	/* toc_length_compressed */
	put_be32(arch + p, 0); p += 4;
	put_be32(arch + p, toclen_u); p += 4;	/* toc_length_uncompressed */
	put_be32(arch + p, 1); p += 4;		/* checksum style: sha1 */

	memcpy(arch + p, toc_z, toc_z_len); p += toc_z_len;
	memcpy(arch + p, chk, 20);
	for (int i = 0; i < n; i++) {
		if (entries[i].is_dir)
			continue;
		memcpy(arch + heap_start + data[i].off, data[i].p, data[i].len);
		for (int k = 0; k < entries[i].nxattr; k++) {
			const struct blob *xb = &ea[eabase[i] + k];
			memcpy(arch + heap_start + xb->off, xb->p, xb->len);
		}
	}

	*out_len = arch_len;
	rc = 0;

out_sbuf:
	sbuf_free(&toc);
out:
	free(toc_z);
	if (data != NULL) {
		for (int i = 0; i < n; i++)
			free(data[i].p);
		free(data);
	}
	if (ea != NULL) {
		for (int i = 0; i < ei; i++)
			free(ea[i].p);
		free(ea);
	}
	free(eabase);
	free(depth);
	if (rc != 0) {
		free(arch);
		*out_len = 0;
		return NULL;
	}
	return arch;
}

int
xar_dump(const unsigned char *pkg, size_t len)
{
	if (len < 28 || memcmp(pkg, "xar!", 4) != 0) {
		fprintf(stderr, "xar: not a xar archive\n");
		return -1;
	}
	uint32_t tocz_len = get_be32(pkg + 12);
	uint32_t toc_len = get_be32(pkg + 20);
	if (tocz_len == 0 || 28 + tocz_len > len) {
		fprintf(stderr, "xar: corrupt table of contents\n");
		return -1;
	}
	unsigned char *toc = NULL;
	uLongf tlen = (uLongf)toc_len;
	if (tlen == 0)
		tlen = (uLongf)(len - 28);
	toc = malloc((size_t)tlen + 1);
	if (toc == NULL)
		return -1;
	uLongf blen = tlen;
	if (uncompress(toc, &blen, pkg + 28, tocz_len) != Z_OK) {
		free(toc);
		fprintf(stderr, "xar: failed to decompress table of contents\n");
		return -1;
	}
	toc[blen] = '\0';

	char *toc_s = (char *)toc;
	char *p = toc_s;
	for (;;) {
		char *fs = strstr(p, "<file ");
		if (fs == NULL)
			break;
		char *fe = strstr(fs + 6, "<file ");
		if (fe == NULL)
			fe = toc_s + blen;

		char *name = NULL;
		char *q = fs;
		while (q < fe) {
			char *nm = strstr(q, "<name>");
			if (nm == NULL || nm >= fe)
				break;
			name = nm;
			q = nm + 6;
		}
		if (name != NULL) {
			char *end = strstr(name + 6, "</name>");
			if (end != NULL && end <= fe)
				printf("%.*s\n", (int)(end - (name + 6)),
				    name + 6);
		}
		p = fe;
	}
	free(toc);
	return 0;
}
