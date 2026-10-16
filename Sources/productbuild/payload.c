/*
 * payload - build a pkg Payload/ Scripts (cpio odc streamed through gzip).
 *
 * Copyright (c) 2026 Sunneva N. Mariu <sunnevanattsol@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * The cpio(1) copy-out is delegated to the system bsdcpio (/usr/bin/cpio)
 * exactly as `find <dir> -print | cpio -o -H odoc | gzip` would produce. The
 * odc record layout is fiddly; rather than re-implement it, we let cpio own it
 * and only own the gzip stream (via zlib) and the enclosing xar.
 *
 * To faithfully replicate Apple pkgbuild's `._*` AppleDouble sidecars (which it
 * emits for any source entry carrying an extended attribute or resource fork),
 * the source tree is staged into a private temp directory: regular files are
 * hard-linked, symlinks recreated, directories rebuilt, and for each
 * xattr-bearing entry a `._<name>` sidecar is materialised with copyfile(3)
 * COPYFILE_PACK. cpio then archives the staged tree.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/xattr.h>
#include <sys/clonefile.h>
#include <copyfile.h>
#include <dirent.h>
#include <zlib.h>

#include "payload.h"

/* --- growable string list --- */

struct svec {
	char **v;
	int n;
	int cap;
};

static int
svec_push(struct svec *s, const char *name)
{
	if (s->n + 1 > s->cap) {
		int cap = s->cap ? s->cap : 32;
		while (cap < s->n + 1)
			cap *= 2;
		char **nv = realloc(s->v, (size_t)cap * sizeof(*nv));
		if (nv == NULL)
			return -1;
		s->v = nv;
		s->cap = cap;
	}
	char *dup = strdup(name);
	if (dup == NULL)
		return -1;
	s->v[s->n++] = dup;
	return 0;
}

static void
svec_free(struct svec *s)
{
	for (int i = 0; i < s->n; i++)
		free(s->v[i]);
	free(s->v);
	s->v = NULL;
	s->n = 0;
	s->cap = 0;
}

/* --- growable byte buffer --- */

struct buf {
	unsigned char *v;
	size_t n;
	size_t cap;
};

static void
buf_init(struct buf *b)
{
	b->v = NULL;
	b->n = 0;
	b->cap = 0;
}

static int
buf_append(struct buf *b, const void *in, size_t n)
{
	if (b->n + n > b->cap) {
		size_t cap = b->cap ? b->cap : 8192;
		while (cap < b->n + n)
			cap *= 2;
		unsigned char *nv = realloc(b->v, cap);
		if (nv == NULL)
			return -1;
		b->v = nv;
		b->cap = cap;
	}
	memcpy(b->v + b->n, in, n);
	b->n += n;
	return 0;
}

static void
buf_free(struct buf *b)
{
	free(b->v);
	b->v = NULL;
	b->n = 0;
	b->cap = 0;
}

/* --- path helpers --- */

/* dirname of relpath (no leading "./"). "" for root or top-level entry. */
static void
dirname_of(const char *relpath, char *out, size_t n)
{
	const char *slash = strrchr(relpath, '/');
	if (slash == NULL) {
		out[0] = '\0';
	} else {
		size_t len = (size_t)(slash - relpath);
		memcpy(out, relpath, len);
		out[len] = '\0';
		if (len >= n)
			out[n - 1] = '\0';
	}
}

static const char *
basename_of(const char *relpath)
{
	const char *slash = strrchr(relpath, '/');
	return slash ? slash + 1 : relpath;
}

/* --- recursive staging with AppleDouble sidecars --- */

struct stage_ctx {
	const char *root;
	const char *stage;
	struct svec *names;
	struct svec nlinks;	/* octal link count per name, same order */
	struct svec uids;	/* octal source uid per name, same order */
	struct svec gids;	/* octal source gid per name, same order */
	int *grp;		/* per name: 1 => member of a hardlink group */
	unsigned long long *gkey;	/* per name: shared inode key */
	int grp_n;
	int grp_cap;
	unsigned long long size_sum;
	int failed;
};

/*
 * Record the cpio inode-group membership of the next record.  pkgbuild keys
 * odc ino by (dev,ino) for regular files with st_nlink > 1: every hardlink
 * shares one ino, and an AppleDouble sidecar shadowing such a file inherits
 * its group.  Directories, symlinks and nlink==1 files each get a fresh ino.
 */
static int
stage_push_ino(struct stage_ctx *ctx, int grouped, unsigned long long key)
{
	if (ctx->grp_n + 1 > ctx->grp_cap) {
		int cap = ctx->grp_cap ? ctx->grp_cap : 32;
		while (cap < ctx->grp_n + 1)
			cap *= 2;
		int *ng = realloc(ctx->grp, (size_t)cap * sizeof(*ng));
		if (ng == NULL)
			return -1;
		ctx->grp = ng;
		unsigned long long *nk = realloc(ctx->gkey,
		    (size_t)cap * sizeof(*nk));
		if (nk == NULL)
			return -1;
		ctx->gkey = nk;
		ctx->grp_cap = cap;
	}
	ctx->grp[ctx->grp_n] = grouped;
	ctx->gkey[ctx->grp_n] = key;
	ctx->grp_n++;
	return 0;
}

/* Record the source entry's link count and ownership for the next cpio
 * record (both a node and any AppleDouble sidecar shadowing it carry the
 * source values).  The Payload archive zeroes uid/gid, but the Scripts
 * archive preserves the source ownership, so record both and let
 * odc_normalize decide. */
static int
stage_push_nlink(struct stage_ctx *ctx, const struct stat *st)
{
	char nbuf[8], ubuf[8], gbuf[8];
	snprintf(nbuf, sizeof nbuf, "%06o", (unsigned)(st->st_nlink & 0777777));
	snprintf(ubuf, sizeof ubuf, "%06o", (unsigned)(st->st_uid & 0777777));
	snprintf(gbuf, sizeof gbuf, "%06o", (unsigned)(st->st_gid & 0777777));
	if (svec_push(&ctx->nlinks, nbuf) != 0)
		return -1;
	if (svec_push(&ctx->uids, ubuf) != 0)
		return -1;
	return svec_push(&ctx->gids, gbuf);
}

/* Copy the source timestamps onto a freshly created staged node so the
 * archived mtimes match pkgbuild's (which preserves the source's). */
static void
stage_set_times(const char *dst, const struct stat *st, int nofollow)
{
	struct timespec ts[2];
	ts[0] = st->st_atimespec;
	ts[1] = st->st_mtimespec;
	utimensat(AT_FDCWD, dst, ts, nofollow ? AT_SYMLINK_NOFOLLOW : 0);
}

/* Stage a regular file as an independent copy.  Hard-linking the source into
 * the stage would bump the source's own st_nlink, corrupting the link counts
 * pkgbuild records for every subsequent entry.  Returns 0 on success, -1 on
 * error. */
static int
stage_copy_file(const char *src, const char *dst, const struct stat *st)
{
	if (clonefile(src, dst, 0) == 0)
		return 0;
	{
		int in = open(src, O_RDONLY);
		if (in < 0)
			return -1;
		int outfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (outfd < 0) {
			close(in);
			return -1;
		}
		unsigned char buf[65536];
		ssize_t k;
		int rc = 0;
		while ((k = read(in, buf, sizeof buf)) > 0) {
			if (write(outfd, buf, (size_t)k) != k) {
				rc = -1;
				break;
			}
		}
		close(in);
		close(outfd);
		if (rc == 0)
			stage_set_times(dst, st, 0);
		return rc;
	}
}

static int
has_xattrs(const char *path)
{
	/* listxattr with XATTR_NOFOLLOW reports the entry's own attrs (not a
	 * symlink target's), avoiding spurious descent into linked trees. */
	ssize_t n = listxattr(path, NULL, 0, XATTR_NOFOLLOW);
	if (n < 0)
		return 0;	/* treat errors as "no sidecar" */
	return n > 0;
}

static void
stage_entry(struct stage_ctx *ctx, const char *relpath)
{
	char src[PATH_MAX];
	char dst[PATH_MAX];
	char name[PATH_MAX];

	if (snprintf(src, sizeof src, "%s/%s", ctx->root,
	    relpath[0] ? relpath : ".") >= (int)sizeof src ||
	    snprintf(dst, sizeof dst, "%s/%s", ctx->stage,
	    relpath[0] ? relpath : ".") >= (int)sizeof dst)
		goto fail;

	struct stat st;
	if (lstat(src, &st) != 0)
		return;		/* ignore vanished entries */

	const char *disp = relpath[0] ? relpath : ".";

	if (S_ISDIR(st.st_mode)) {
		if (mkdir(dst, st.st_mode & 0777) != 0 && errno != EEXIST)
			goto fail;
		if (chmod(dst, st.st_mode & 0777) != 0)
			goto fail;
	} else if (S_ISLNK(st.st_mode)) {
		char target[PATH_MAX];
		ssize_t t = readlink(src, target, sizeof target - 1);
		if (t < 0)
			goto fail;
		target[t] = '\0';
		if (symlink(target, dst) != 0 && errno != EEXIST)
			goto fail;
		stage_set_times(dst, &st, 1);
	} else if (S_ISREG(st.st_mode)) {
		if (stage_copy_file(src, dst, &st) < 0)
			goto fail;
	}

	if (relpath[0]) {
		if (snprintf(name, sizeof name, "./%s", disp) >= (int)sizeof name)
			goto fail;
	} else {
		snprintf(name, sizeof name, ".");
	}
	ctx->size_sum += ((unsigned long long)st.st_size + 511) / 512 * 512;
	if (svec_push(ctx->names, name) != 0)
		goto fail;
	if (stage_push_nlink(ctx, &st) != 0)
		goto fail;
	if (stage_push_ino(ctx, S_ISREG(st.st_mode) && st.st_nlink > 1,
	    st.st_ino) != 0)
		goto fail;

	if (S_ISDIR(st.st_mode)) {
		/* descend in readdir order, like a real copy */
		DIR *d = opendir(src);
		if (d != NULL) {
			struct dirent *de;
			while ((de = readdir(d)) != NULL) {
				if (strcmp(de->d_name, ".") == 0 ||
				    strcmp(de->d_name, "..") == 0)
					continue;
				char child[PATH_MAX];
				int clen = relpath[0] ?
				    snprintf(child, sizeof child, "%s/%s", relpath,
				        de->d_name) :
				    snprintf(child, sizeof child, "%s", de->d_name);
				if (clen < 0 || (size_t)clen >= sizeof child)
					continue;
				stage_entry(ctx, child);
				if (ctx->failed)
					break;
			}
			closedir(d);
		}
		/* creating children bumped the mtime; restore the source's */
		stage_set_times(dst, &st, 0);
	}

	/* AppleDouble sidecar, emitted post-order: pkgbuild archives a
	 * directory's sidecar only after its entire subtree. */
	if (relpath[0] && (S_ISDIR(st.st_mode) || S_ISREG(st.st_mode) ||
	    S_ISLNK(st.st_mode)) && has_xattrs(src)) {
		char parent[PATH_MAX];
		const char *base = basename_of(relpath);
		dirname_of(relpath, parent, sizeof parent);

		char sid[PATH_MAX];
		snprintf(sid, sizeof sid, "._%s", base);

		char sdst[PATH_MAX];
		char sname[PATH_MAX];
		if (parent[0]) {
			snprintf(sdst, sizeof sdst, "%s/%s/%s", ctx->stage,
			    parent, sid);
			snprintf(sname, sizeof sname, "./%s/%s", parent, sid);
		} else {
			snprintf(sdst, sizeof sdst, "%s/%s", ctx->stage, sid);
			snprintf(sname, sizeof sname, "./%s", sid);
		}

		uint32_t cflags = COPYFILE_PACK | COPYFILE_XATTR;
		if (S_ISLNK(st.st_mode))
			cflags |= COPYFILE_NOFOLLOW;
		if (copyfile(src, sdst, NULL, cflags) == 0) {
			chmod(sdst, st.st_mode & 0666);
			if (svec_push(ctx->names, sname) != 0)
				goto fail;
			if (stage_push_nlink(ctx, &st) != 0)
				goto fail;
			if (stage_push_ino(ctx,
			    S_ISREG(st.st_mode) && st.st_nlink > 1,
			    st.st_ino) != 0)
				goto fail;
		}
	}
	return;

fail:
	ctx->failed = 1;
}

/* --- cpio -o -H odc reading the name list from a temp file --- */

static int
run_cpio(const char *stage, struct svec *names, struct buf *out)
{
	char tmpl[] = "/tmp/pkgbuild.XXXXXX";
	int tf = mkstemp(tmpl);
	if (tf < 0)
		return -1;
	for (int i = 0; i < names->n; i++) {
		if (write(tf, names->v[i], strlen(names->v[i])) < 0 ||
		    write(tf, "\n", 1) < 0) {
			close(tf);
			unlink(tmpl);
			return -1;
		}
	}
	close(tf);

	int pipefd[2];
	if (pipe(pipefd) != 0) {
		unlink(tmpl);
		return -1;
	}

	pid_t pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		unlink(tmpl);
		return -1;
	}
	if (pid == 0) {
		int in = open(tmpl, O_RDONLY);
		if (in >= 0) {
			dup2(in, STDIN_FILENO);
			close(in);
		}
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		int dev = open("/dev/null", O_WRONLY);
		if (dev >= 0) {
			dup2(dev, STDERR_FILENO);
			close(dev);
		}
		if (chdir(stage) != 0)
			_exit(127);
		execlp("cpio", "cpio", "-o", "-H", "odc", (char *)NULL);
		_exit(127);
	}

	close(pipefd[1]);
	char tmp[8192];
	ssize_t k;
	while ((k = read(pipefd[0], tmp, sizeof tmp)) > 0) {
		if (buf_append(out, tmp, (size_t)k) != 0) {
			close(pipefd[0]);
			waitpid(pid, NULL, 0);
			unlink(tmpl);
			return -1;
		}
	}
	close(pipefd[0]);
	int status = 0;
	waitpid(pid, &status, 0);
	unlink(tmpl);

	return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* Rewrite the odc (070707) header fields pkgbuild sets from the source, which
 * cpio (staging into fresh nodes) cannot know.  The source link count is always
 * restored.  Ownership is restored from the source only when preserve_owner is
 * set (the Scripts archive); the Payload archive sanitizes uid/gid to 0/0
 * ("recommended" ownership).  The ino field is a fresh sequential id per
 * record, except that entries in a hardlink group (regular files with
 * st_nlink > 1, and their sidecars) share the id assigned to the group's first
 * member. */
static void
odc_normalize(struct buf *b, const struct svec *nlinks, const struct svec *uids,
    const struct svec *gids, int preserve_owner, const int *grp,
    const unsigned long long *gkey, int grp_n)
{
	struct { unsigned long long key; unsigned val; } *map = NULL;
	int map_n = 0;
	int map_cap = 0;

	size_t i = 0;
	int k = 0;
	unsigned ctr = 0;
	while (i + 76 <= b->n && memcmp(b->v + i, "070707", 6) == 0) {
		char nbuf[12], fbuf[13];
		memcpy(nbuf, b->v + i + 59, 6);
		nbuf[6] = '\0';
		memcpy(fbuf, b->v + i + 65, 11);
		fbuf[11] = '\0';
		long ns = strtol(nbuf, NULL, 8);
		long fs = strtol(fbuf, NULL, 8);
		unsigned val;
		if (k < grp_n && grp[k]) {
			int found = -1;
			for (int j = 0; j < map_n; j++) {
				if (map[j].key == gkey[k]) {
					found = j;
					break;
				}
			}
			if (found >= 0) {
				val = map[found].val;
			} else {
				val = ctr++;
				if (map_n == map_cap) {
					int cap = map_cap ? map_cap * 2 : 32;
					void *nm = realloc(map,
					    (size_t)cap * sizeof(*map));
					if (nm != NULL) {
						map = nm;
						map_cap = cap;
					}
				}
				if (map_n < map_cap) {
					map[map_n].key = gkey[k];
					map[map_n].val = val;
					map_n++;
				}
			}
		} else {
			val = ctr++;
		}
		char ibuf[8];
		snprintf(ibuf, sizeof ibuf, "%06o", val & 0777777);
		memset(b->v + i + 6, '0', 6);	/* dev */
		memcpy(b->v + i + 12, ibuf, 6);	/* ino */
		if (preserve_owner && k < uids->n && k < gids->n) {
			memcpy(b->v + i + 24, uids->v[k], 6);	/* uid */
			memcpy(b->v + i + 30, gids->v[k], 6);	/* gid */
		} else {
			memset(b->v + i + 24, '0', 6);	/* uid */
			memset(b->v + i + 30, '0', 6);	/* gid */
		}
		if (k < nlinks->n)
			memcpy(b->v + i + 36, nlinks->v[k], 6);	/* nlink */
		k++;
		i += 76 + (size_t)ns + (size_t)fs;
	}
	free(map);
}

/* --- gzip (RFC 1952) via raw deflate (windowBits = 15 + 16) --- */

static int
gzip_bytes(const void *in, size_t n, unsigned char **out, size_t *out_len)
{
	z_stream s;
	memset(&s, 0, sizeof s);
	if (deflateInit2(&s, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8,
	    Z_DEFAULT_STRATEGY) != Z_OK)
		return -1;

	struct buf b;
	buf_init(&b);

	s.next_in = (Bytef *)in;
	s.avail_in = (uInt)n;

	for (;;) {
		unsigned char chunk[16384];
		s.next_out = chunk;
		s.avail_out = (uInt)sizeof chunk;
		int flush = (s.avail_in == 0) ? Z_FINISH : Z_NO_FLUSH;
		int r = deflate(&s, flush);
		size_t have = sizeof chunk - s.avail_out;
		if (have > 0) {
			if (buf_append(&b, chunk, have) != 0) {
				deflateEnd(&s);
				buf_free(&b);
				return -1;
			}
		}
		if (r == Z_STREAM_END)
			break;
		if (r != Z_OK) {
			deflateEnd(&s);
			buf_free(&b);
			return -1;
		}
	}
	deflateEnd(&s);

	/* Match pkgbuild's gzip header: OS byte is Unix (0x03), not zlib's
	 * platform default on macOS. */
	if (b.n >= 10 && b.v[0] == 0x1f && b.v[1] == 0x8b)
		b.v[9] = 0x03;

	*out = b.v;
	*out_len = b.n;
	return 0;
}

/* --- recursive remove --- */

static void
remove_tree(const char *path)
{
	struct stat st;
	if (lstat(path, &st) != 0)
		return;
	if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
		DIR *d = opendir(path);
		if (d != NULL) {
			struct dirent *de;
			while ((de = readdir(d)) != NULL) {
				if (strcmp(de->d_name, ".") == 0 ||
				    strcmp(de->d_name, "..") == 0)
					continue;
				char child[PATH_MAX];
				snprintf(child, sizeof child, "%s/%s", path, de->d_name);
				remove_tree(child);
			}
			closedir(d);
		}
		rmdir(path);
	} else {
		unlink(path);
	}
}

int
payload_build(const char *root, struct payload *out, int preserve_owner)
{
	char tmpl[] = "/tmp/productbuild-stage.XXXXXX";
	char *stage = mkdtemp(tmpl);
	if (stage == NULL)
		return -1;

	struct svec names;
	names.v = NULL;
	names.n = 0;
	names.cap = 0;

	struct buf odc;
	buf_init(&odc);

	struct stage_ctx ctx;
	ctx.root = root;
	ctx.stage = stage;
	ctx.names = &names;
	ctx.nlinks.v = NULL;
	ctx.nlinks.n = 0;
	ctx.nlinks.cap = 0;
	ctx.uids.v = NULL;
	ctx.uids.n = 0;
	ctx.uids.cap = 0;
	ctx.gids.v = NULL;
	ctx.gids.n = 0;
	ctx.gids.cap = 0;
	ctx.grp = NULL;
	ctx.gkey = NULL;
	ctx.grp_n = 0;
	ctx.grp_cap = 0;
	ctx.size_sum = 0;
	ctx.failed = 0;
	stage_entry(&ctx, "");

	int rc = -1;
	if (ctx.failed)
		goto done;
	if (names.n == 0)
		goto done;

	if (run_cpio(stage, &names, &odc) != 0)
		goto done;
	odc_normalize(&odc, &ctx.nlinks, &ctx.uids, &ctx.gids, preserve_owner,
	    ctx.grp, ctx.gkey, ctx.grp_n);

	unsigned char *gz = NULL;
	size_t gzlen = 0;
	if (gzip_bytes(odc.v, odc.n, &gz, &gzlen) != 0)
		goto done;

	out->data = gz;
	out->size = gzlen;
	out->uncompressed = odc.n;
	out->file_count = names.n;
	out->install_kbytes = (size_t)(ctx.size_sum / 1024);
	rc = 0;

done:
	buf_free(&odc);
	svec_free(&names);
	svec_free(&ctx.nlinks);
	svec_free(&ctx.uids);
	svec_free(&ctx.gids);
	free(ctx.grp);
	free(ctx.gkey);
	remove_tree(stage);
	return rc;
}

int
payload_stage(const char *root, char **stage_out, struct payload *out,
    int preserve_owner)
{
	char tmpl[] = "/tmp/productbuild-stage.XXXXXX";
	char *stage = mkdtemp(tmpl);
	if (stage == NULL)
		return -1;

	struct svec names;
	names.v = NULL;
	names.n = 0;
	names.cap = 0;

	struct buf odc;
	buf_init(&odc);

	struct stage_ctx ctx;
	ctx.root = root;
	ctx.stage = stage;
	ctx.names = &names;
	ctx.nlinks.v = NULL;
	ctx.nlinks.n = 0;
	ctx.nlinks.cap = 0;
	ctx.uids.v = NULL;
	ctx.uids.n = 0;
	ctx.uids.cap = 0;
	ctx.gids.v = NULL;
	ctx.gids.n = 0;
	ctx.gids.cap = 0;
	ctx.grp = NULL;
	ctx.gkey = NULL;
	ctx.grp_n = 0;
	ctx.grp_cap = 0;
	ctx.size_sum = 0;
	ctx.failed = 0;
	stage_entry(&ctx, "");

	int rc = -1;
	if (ctx.failed)
		goto done;
	if (names.n == 0)
		goto done;

	if (run_cpio(stage, &names, &odc) != 0)
		goto done;
	odc_normalize(&odc, &ctx.nlinks, &ctx.uids, &ctx.gids, preserve_owner,
	    ctx.grp, ctx.gkey, ctx.grp_n);

	unsigned char *gz = NULL;
	size_t gzlen = 0;
	if (gzip_bytes(odc.v, odc.n, &gz, &gzlen) != 0)
		goto done;

	out->data = gz;
	out->size = gzlen;
	out->uncompressed = odc.n;
	out->file_count = names.n;
	out->install_kbytes = (size_t)(ctx.size_sum / 1024);

	rc = 0;

done:
	buf_free(&odc);
	svec_free(&names);
	svec_free(&ctx.nlinks);
	svec_free(&ctx.uids);
	svec_free(&ctx.gids);
	free(ctx.grp);
	free(ctx.gkey);
	if (rc != 0) {
		remove_tree(stage);
		return rc;
	}
	*stage_out = strdup(stage);
	if (*stage_out == NULL) {
		remove_tree(stage);
		return -1;
	}
	return 0;
}
