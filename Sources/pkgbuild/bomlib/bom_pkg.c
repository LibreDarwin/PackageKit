/*
 * bom_pkg - clean-room BOM writer matching Apple pkgbuild(1).
 *
 * Copyright (c) 2026 Sunneva N. Mariu <sunnevanattsol@gmail.com>
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Image layout (offsets from /usr/bin/pkgbuild output):
 *   [0]      header (32 bytes)
 *   [0x200]  dense block map (blocks allocated in call order)
 *   [.]      BOMStore index, written once per commit (4 + 2730*8 + 60)
 *   [.]      vars section (named-block index, 60 bytes at the end)
 *
 * Block ids:
 *   1 BomInfo   2 Paths tree-hdr   3 Paths leaf   4 HLIndex tree-hdr
 *   5 HLIndex leaf   6 VIndex hdr   7 Size64 hdr   8 Size64 leaf
 *   9 MTime hdr  10 MTime leaf
 *   11+3*(p-1)  PathRecord / name / pii   per path (pid order)
 *   86+4*i      quad tree/leaf/prptr/treeptr per path (sorted-path order)
 */

#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "bom_cksum.h"
#include "bom_pkg.h"
#include "bom_btree.h"

static uint32_t g_paths_leaf[4096], g_paths_nl, g_paths_int;
static uint32_t g_hl_leaf[4096], g_hl_nl, g_hl_int;

#define IDX_POOL   2730u
#define IDX_SIZE   (4u + 8u * IDX_POOL + 60u)	/* 0x5590 */
#define MAP_BASE   0x200u
#define OVFL       0x10000u

#define ID_INFO    1u
#define ID_PATHS_H 2u
#define ID_PATHS_L 3u
#define ID_HL_H    4u
#define ID_HL_L    5u
#define ID_VIX     6u
#define ID_SZ_H    7u
#define ID_SZ_L    8u
#define ID_MT_H    9u
#define ID_MT_L    10u

typedef struct frec {
	struct frec *next;
	uint32_t addr;
	uint32_t size;
} frec;

typedef struct {
	frec **buckets;		/* exact-size lists, head == newest */
	frec *ov;		/* oversized regions */
	uint32_t hi;
} alloc;

#define BM_MAXSLICE 64

typedef struct {
	uint32_t cputype;
	uint32_t subtype;
	uint64_t off;
	uint32_t len;
	uint32_t cksum;
} bm_mslice;

typedef struct {
	uint32_t pid;
	uint32_t parent;
	char *name;
	char *rel;
	int type;		/* 1 reg, 2 dir, 3 lnk */
	int sidecar;
	uint32_t mode;
	uint32_t mtime;
	uint32_t size;
	uint32_t cksum;
	uint32_t lnklen;
	char *target;
	int macho;
	int nsl;
	bm_mslice sl[BM_MAXSLICE];
	uint32_t recsize;
	uint32_t prblk, fileblk, piiblk, qbase;
	uint32_t br;		/* breadth-first (discovery) rank */
} ent;

static int g_fail;

static void
put32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);
	p[3] = (unsigned char)v;
}

static void
put16(unsigned char *p, uint16_t v)
{
	p[0] = (unsigned char)(v >> 8);
	p[1] = (unsigned char)v;
}

static uint32_t
r32(const unsigned char *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	    ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int
macho_slices(const unsigned char *hdr, size_t hlen, uint64_t fsize,
    bm_mslice *sl, int maxsl, int *is_fat)
{
	uint32_t magic;
	if (hlen < 4)
		return 0;
	*is_fat = 0;
	magic = r32(hdr);
	switch (magic) {
	case 0xcefaedfe:
	case 0xcffaedfe:
	case 0xfeedface:
	case 0xfeedfacf:
		if (hlen < 12 || maxsl < 1)
			return 0;
		if (magic == 0xcefaedfe || magic == 0xcffaedfe) {
			sl[0].cputype = (uint32_t)hdr[4] |
			    ((uint32_t)hdr[5] << 8) |
			    ((uint32_t)hdr[6] << 16) |
			    ((uint32_t)hdr[7] << 24);
			sl[0].subtype = (uint32_t)hdr[8] |
			    ((uint32_t)hdr[9] << 8) |
			    ((uint32_t)hdr[10] << 16) |
			    ((uint32_t)hdr[11] << 24);
		} else {
			sl[0].cputype = r32(hdr + 4);
			sl[0].subtype = r32(hdr + 8);
		}
		sl[0].off = 0;
		sl[0].len = (uint32_t)fsize;
		sl[0].cksum = 0;
		return 1;
	case 0xcafebabe:
		if (hlen < 8 || maxsl < 1)
			return 0;
		{
			uint32_t n = r32(hdr + 4), i;
			size_t need;
			if (n == 0 || n > (uint32_t)maxsl)
				return 0;
			need = 8 + 20 * (size_t)n;
			if (need > hlen)
				return 0;
			*is_fat = 1;
			for (i = 0; i < n; i++) {
				const unsigned char *fe = hdr + 8 + 20 * i;
				uint64_t off = r32(fe + 8);
				uint32_t len = r32(fe + 12);
				if (off > fsize || len > fsize - off)
					return 0;
				sl[i].cputype = r32(fe + 0);
				sl[i].subtype = r32(fe + 4);
				sl[i].off = off;
				sl[i].len = len;
				sl[i].cksum = 0;
			}
			return (int)n;
		}
	default:
		return 0;
	}
}

/* ---- free-list -------------------------------------------------------- */

static void
fl_push(alloc *a, uint32_t addr, uint32_t size)
{
	frec *f;
	if (size == 0)
		return;
	if (size >= OVFL) {
		f = malloc(sizeof(*f));
		if (f == NULL)
			return;
		f->addr = addr;
		f->size = size;
		f->next = a->ov;
		a->ov = f;
		return;
	}
	f = malloc(sizeof(*f));
	if (f == NULL)
		return;
	f->addr = addr;
	f->size = size;
	f->next = a->buckets[size];
	a->buckets[size] = f;
}

static uint32_t
fl_take(alloc *a, uint32_t size)
{
	uint32_t s;
	frec *f;
	if (size != 0 && size < OVFL && a->buckets[size] != NULL) {
		f = a->buckets[size];
		a->buckets[size] = f->next;
		uint32_t addr = f->addr;
		free(f);
		return addr;
	}
	for (s = size + 1; s < OVFL; s++) {
		if (a->buckets[s] != NULL) {
			f = a->buckets[s];
			a->buckets[s] = f->next;
			uint32_t addr = f->addr;
			free(f);
			fl_push(a, addr + size, s - size);
			return addr;
		}
	}
	{
		frec *bf = NULL, **bp = NULL, **pp;
		for (pp = &a->ov; *pp != NULL; pp = &(*pp)->next)
			if ((*pp)->size >= size && (bf == NULL || (*pp)->size < bf->size)) {
				bf = *pp;
				bp = pp;
			}
		if (bf != NULL) {
			uint32_t addr = bf->addr, osz = bf->size;
			*bp = bf->next;
			free(bf);
			if (osz > size)
				fl_push(a, addr + size, osz - size);
			return addr;
		}
	}
	{
		uint32_t addr = a->hi;
		a->hi += size;
		return addr;
	}
}

static void
fl_destroy(alloc *a)
{
	if (a->buckets == NULL)
		return;
	for (uint32_t s = 0; s < OVFL; s++) {
		frec *f = a->buckets[s];
		while (f != NULL) {
			frec *n = f->next;
			free(f);
			f = n;
		}
	}
	while (a->ov != NULL) {
		frec *n = a->ov->next;
		free(a->ov);
		a->ov = n;
	}
	free(a->buckets);
	a->buckets = NULL;
}

/* pairs flattened for the 60-byte index trailer */
static void
fl_pairs(alloc *a, uint32_t *addr, uint32_t *size, uint32_t *count)
{
	uint32_t k = 0;
	for (uint32_t s = 0; s < OVFL; s++)
		for (frec *f = a->buckets[s]; f != NULL; f = f->next) {
			addr[k] = f->addr;
			size[k] = s;
			k++;
		}
	for (frec *f = a->ov; f != NULL; f = f->next) {
		addr[k] = f->addr;
		size[k] = f->size;
		k++;
	}
	*count = k;
}

/* ---- filesystem scan -------------------------------------------------- */

static int
has_xattrs(const char *path)
{
	return listxattr(path, NULL, 0, XATTR_NOFOLLOW) > 0;
}

static unsigned char *
read_file(const char *path, uint32_t *out_len)
{
	int fd = open(path, O_RDONLY);
	struct stat st;
	unsigned char *buf;
	size_t got = 0, want;
	if (fd < 0)
		return NULL;
	if (fstat(fd, &st) != 0 || st.st_size < 0) {
		close(fd);
		return NULL;
	}
	want = (size_t)st.st_size;
	buf = malloc(want == 0 ? 1 : want);
	if (buf == NULL) {
		close(fd);
		return NULL;
	}
	while (got < want) {
		ssize_t r = read(fd, buf + got, want - got);
		if (r < 0) {
			free(buf);
			close(fd);
			return NULL;
		}
		if (r == 0)
			break;
		got += (size_t)r;
	}
	close(fd);
	*out_len = (uint32_t)got;
	return buf;
}

static char *
path_join(const char *root, const char *rel)
{
	size_t rl = strlen(root), ll = strlen(rel);
	char *p = malloc(rl + 1 + ll + 1);
	if (p == NULL)
		return NULL;
	memcpy(p, root, rl);
	p[rl] = '/';
	memcpy(p + rl + 1, rel, ll);
	p[rl + 1 + ll] = '\0';
	return p;
}

static char *
chld_rel(const char *prel, const char *name)
{
	size_t pl = strlen(prel), nl = strlen(name);
	char *r;
	if (pl == 0) {
		r = malloc(nl + 1);
		if (r != NULL)
			memcpy(r, name, nl + 1);
		return r;
	}
	r = malloc(pl + 1 + nl + 1);
	if (r == NULL)
		return NULL;
	memcpy(r, prel, pl);
	r[pl] = '/';
	memcpy(r + pl + 1, name, nl + 1);
	return r;
}

static char *
sidecar_name(const char *name)
{
	size_t n = strlen(name);
	char *s = malloc(n + 3);
	if (s == NULL)
		return NULL;
	s[0] = '.';
	s[1] = '_';
	memcpy(s + 2, name, n + 1);
	return s;
}

static char *
sidecar_rel(const char *prel, const char *name)
{
	size_t pl = strlen(prel), nl = strlen(name);
	char *r = malloc(pl + 3 + nl + 1);
	if (r == NULL)
		return NULL;
	memcpy(r, prel, pl);
	r[pl] = '/';
	r[pl + 1] = '.';
	r[pl + 2] = '_';
	memcpy(r + pl + 3, name, nl + 1);
	return r;
}

static void
scan(const char *abs, const char *rel, const char *leaf, uint32_t parent,
    ent *ents, uint32_t *n, uint32_t cap)
{
	struct stat st;
	ent *e;
	uint32_t pid;
	DIR *d;
	struct dirent *de;

	if (*n >= cap) {
		g_fail = 1;
		return;
	}
	pid = *n + 1;
	e = &ents[(*n)++];
	memset(e, 0, sizeof(*e));
	if (lstat(abs, &st) != 0) {
		g_fail = 1;
		return;
	}
	e->pid = pid;
	e->parent = parent;
	e->name = strdup(leaf);
	e->rel = strdup(rel);
	e->type = S_ISDIR(st.st_mode) ? 2 : (S_ISLNK(st.st_mode) ? 3 : 1);
	e->mode = (uint32_t)st.st_mode;
	e->mtime = (uint32_t)st.st_mtime;
	e->size = (uint32_t)st.st_size;
	if (e->type == 3) {
		char lb[4096];
		ssize_t l = readlink(abs, lb, sizeof(lb) - 1);
		uint32_t tl = (l > 0) ? (uint32_t)l : 0;
		lb[tl] = '\0';
		e->lnklen = tl + 1;
		e->cksum = (tl > 0) ? bm_cksum(lb, tl) : 0;
		e->target = malloc(tl + 1);
		if (e->target != NULL)
			memcpy(e->target, lb, tl + 1);
	} else if (e->type == 1) {
		uint32_t fl = 0;
		unsigned char *fb = read_file(abs, &fl);
		if (fb != NULL) {
			int is_fat = 0, k;
			e->cksum = bm_cksum(fb, fl);
			e->nsl = macho_slices(fb, fl, e->size, e->sl,
			    BM_MAXSLICE, &is_fat);
			if (e->nsl > 0) {
				e->macho = is_fat ? 2 : 1;
				for (k = 0; k < e->nsl; k++) {
					if (is_fat)
						e->sl[k].cksum = bm_cksum(
						    fb + e->sl[k].off,
						    e->sl[k].len);
					else
						e->sl[k].cksum = e->cksum;
				}
			}
			free(fb);
		}
	}
	if (e->type != 2)
		return;

	d = opendir(abs);
	if (d == NULL) {
		g_fail = 1;
		return;
	}
	while ((de = readdir(d)) != NULL) {
		char *crel, *cabs;
		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;
		crel = chld_rel(rel, de->d_name);
		cabs = path_join(abs, de->d_name);
		if (crel == NULL || cabs == NULL) {
			free(crel);
			free(cabs);
			g_fail = 1;
			continue;
		}
		scan(cabs, crel, de->d_name, pid, ents, n, cap);
		free(crel);
		free(cabs);
	}
	closedir(d);
}

/* ---- ordering --------------------------------------------------------- */

static int
cmp_dfs(const void *pa, const void *pb)
{
	const ent *a = *(ent *const *)pa, *b = *(ent *const *)pb;
	return strcmp(a->rel, b->rel);
}

static int
cmp_paths(const void *pa, const void *pb)
{
	const ent *a = *(ent *const *)pa, *b = *(ent *const *)pb;
	if (a->parent != b->parent)
		return a->parent < b->parent ? -1 : 1;
	return strcmp(a->name, b->name);
}

static int
cmp_sidecar(const void *pa, const void *pb)
{
	const ent *a = pa, *b = pb;
	return strcmp(a->rel, b->rel);
}

/* ---- driver ----------------------------------------------------------- */

typedef struct {
	uint32_t *addr;
	uint32_t *size;
	unsigned char **data;
	uint32_t nblocks;
} blktab;

static void
put_var(unsigned char *p, uint32_t nv, const uint32_t *ids, const char **nm)
{
	uint32_t o = 4, j;
	put32(p, nv);
	for (j = 0; j < nv; j++) {
		size_t l = strlen(nm[j]);
		put32(p + o, ids[j]);
		p[o + 4] = (unsigned char)l;
		memcpy(p + o + 5, nm[j], l);
		o += 5 + (uint32_t)l;
	}
}

unsigned char *
bm_pkg_build(const char *root, size_t *out_len)
{
	ent *ents = NULL;
	uint32_t cap = 64, n = 0, nreal, nside, i;
	unsigned char *out = NULL;
	blktab bt;
	alloc A;
	uint32_t *varlen = (uint32_t[]){ 16, 26, 38, 49, 60 };
	uint32_t ids5[5] = { ID_INFO, ID_PATHS_H, ID_HL_H, ID_VIX, ID_MT_H };
	const char *nm5[5] = { "BomInfo", "Paths", "HLIndex", "VIndex", "Size64" };
	uint32_t var_addr[5], info12 = 0, commits[2], idx_size = IDX_SIZE;
	uint32_t pool = IDX_POOL;
	ent **dorder = NULL, **porder = NULL;
	btree_plan pplan, hplan;
	uint32_t ninfo, narch = 0;
	uint32_t arcp[BM_MAXSLICE];
	uint64_t arsz[BM_MAXSLICE];

	memset(&bt, 0, sizeof(bt));
	memset(&A, 0, sizeof(A));
	memset(&pplan, 0, sizeof(pplan));
	memset(&hplan, 0, sizeof(hplan));

	ents = calloc(cap, sizeof(*ents));
	if (ents == NULL)
		return NULL;
	for (;;) {
		g_fail = 0;
		n = 0;
		scan(root, ".", ".", 0, ents, &n, cap);
		if (!g_fail)
			break;
		for (i = 0; i < n; i++) {
			free(ents[i].name);
			free(ents[i].rel);
		}
		cap *= 2;
		{
			ent *ne = realloc(ents, (size_t)cap * sizeof(*ents));
			if (ne == NULL)
				goto done;
			ents = ne;
		}
	}
	nreal = n;

	/* sidecars: every non-root entry carrying xattrs gets a ._ record */
	{
		ent *tmp = calloc(nreal, sizeof(*tmp));
		uint32_t m = 0;
		if (tmp == NULL)
			goto done;
		for (i = 1; i < nreal; i++) {
			char *abs = path_join(root, ents[i].rel);
			if (abs == NULL)
				continue;
			if (has_xattrs(abs))
				tmp[m++] = ents[i];
			free(abs);
		}
		qsort(tmp, m, sizeof(*tmp), cmp_sidecar);
		nside = m;
		if (nside > 0) {
			ent *ne = realloc(ents, (size_t)(nreal + nside) * sizeof(*ents));
			if (ne == NULL) {
				free(tmp);
				goto done;
			}
			ents = ne;
			for (i = 0; i < nside; i++) {
				ent *sh = &tmp[i];
				ent *e = &ents[nreal + i];
				memset(e, 0, sizeof(*e));
				e->pid = nreal + i + 1;
				e->parent = sh->parent;
				e->name = sidecar_name(sh->name);
				e->rel = sidecar_rel(ents[sh->parent - 1].rel,
				    sh->name);
				e->type = 1;
				e->sidecar = 1;
				e->mode = sh->mode;
				e->recsize = 31;
			}
		}
		free(tmp);
	}
	n = nreal + nside;

	bt.nblocks = 10 + 7 * n;
	while (pool < bt.nblocks)
		pool = (pool & 1u) ? pool * 2 : pool * 2 + 1;
	bt.addr = calloc(bt.nblocks + 1, sizeof(uint32_t));
	bt.size = calloc(bt.nblocks + 1, sizeof(uint32_t));
	bt.data = calloc(bt.nblocks + 1, sizeof(unsigned char *));
	dorder = malloc(n * sizeof(*dorder));
	porder = malloc(n * sizeof(*porder));
	if (bt.addr == NULL || bt.size == NULL || bt.data == NULL ||
	    dorder == NULL || porder == NULL)
		goto done;

	for (i = 0; i < n; i++) {
		ent *e = &ents[i];
		e->recsize = (e->type == 1 && !e->sidecar) ? 35 : 31;
		if (e->type == 1 && e->macho)
			e->recsize = 40 + 16 * (uint32_t)e->nsl;
		if (e->type == 3)
			e->recsize = 31 + e->lnklen + 8;
		dorder[i] = porder[i] = e;
	}
	qsort(dorder, n, sizeof(*dorder), cmp_dfs);
	qsort(porder, n, sizeof(*porder), cmp_paths);

	/* Breadth-first (discovery) rank of every entry: root first, then each
	 * node's children in ascending pid order.  This is the HLIndex sort key. */
	{
		uint32_t *q = malloc(n ? n * sizeof(uint32_t) : 1);
		uint32_t qh = 0, qt = 0, z, rank = 0;
		if (q == NULL)
			goto done;
		q[qt++] = 0;	/* root entry */
		for (i = 0; i < n; i++)
			ents[i].br = 0;
		while (qh < qt) {
			uint32_t cur = q[qh++];
			uint32_t pid = ents[cur].pid;
			ents[cur].br = rank++;
			for (z = 1; z < n; z++)
				if (ents[z].parent == pid && z != cur)
					q[qt++] = z;
		}
		free(q);
	}

	/* Build both tree layout plans up front.  The Paths tree is keyed by
	 * (parent,name) and inserted in path (pid) order; the HLIndex tree is
	 * keyed by breadth-first rank and inserted in dfs (sorted-path) order. */
	{
		btree_key *keys = calloc(n ? n : 1, sizeof(btree_key));
		uint32_t *insord = calloc(n ? n : 1, sizeof(uint32_t));
		uint32_t *hlrank = calloc(n ? n : 1, sizeof(uint32_t));
		memset(&pplan, 0, sizeof(pplan));
		memset(&hplan, 0, sizeof(hplan));
		if (keys == NULL || insord == NULL || hlrank == NULL) {
			free(keys); free(insord); free(hlrank);
			goto done;
		}
		for (i = 0; i < n; i++) {
			keys[i].parent = ents[i].parent;
			keys[i].name = ents[i].name;
			insord[i] = (uint32_t)i;
			hlrank[i] = ents[i].br;
		}
		bom_btree_plan(keys, (size_t)n, insord, &pplan);
		for (i = 0; i < n; i++)
			insord[i] = (uint32_t)(dorder[i] - ents);
		bom_btree_plan_ranks(hlrank, (size_t)n, insord, &hplan);
		free(keys);
		free(insord);
		free(hlrank);
	}
	narch = 0;
	for (i = 0; i < n; i++) {
		ent *e = &ents[i];
		int k;
		if (!e->macho)
			continue;
		for (k = 0; k < e->nsl; k++) {
			uint32_t j;
			for (j = 0; j < narch; j++)
				if (arcp[j] == e->sl[k].cputype)
					break;
			if (j == narch) {
				if (narch >= BM_MAXSLICE)
					break;
				arcp[narch] = e->sl[k].cputype;
				arsz[narch] = 0;
				narch++;
			}
			arsz[j] += e->sl[k].len;
		}
	}
	ninfo = 1 + narch;
	bt.size[ID_INFO] = 12 + 16 * ninfo;
	bt.size[ID_PATHS_H] = 21;
	bt.size[ID_PATHS_L] = 4096;
	bt.size[ID_HL_H] = 21;
	bt.size[ID_HL_L] = 4096;
	bt.size[ID_VIX] = 13;
	bt.size[ID_SZ_H] = 21;
	bt.size[ID_SZ_L] = 128;
	bt.size[ID_MT_H] = 21;
	bt.size[ID_MT_L] = 4096;

	/* ---- pass 1: allocate every block, capture free state ---- */
	A.buckets = calloc(OVFL, sizeof(*A.buckets));
	if (A.buckets == NULL)
		goto done;
	A.hi = MAP_BASE;
	{
		uint32_t prev = 0, prevsz = 0;
#define NAMED(k) do {						\
		if (prev != 0)					\
			fl_push(&A, prev, prevsz);		\
		var_addr[k] = fl_take(&A, varlen[k]);		\
		prev = var_addr[k];				\
		prevsz = varlen[k];				\
	} while (0)
		NAMED(0);
		info12 = fl_take(&A, 12);
		NAMED(1);
		bt.addr[ID_PATHS_L] = fl_take(&A, 4096);
		bt.addr[ID_PATHS_H] = fl_take(&A, 21);
		NAMED(2);
		bt.addr[ID_HL_L] = fl_take(&A, 4096);
		bt.addr[ID_HL_H] = fl_take(&A, 21);
		NAMED(3);
		bt.addr[ID_SZ_L] = fl_take(&A, 128);
		bt.addr[ID_SZ_H] = fl_take(&A, 21);
		bt.addr[ID_VIX] = fl_take(&A, 13);
		NAMED(4);
		bt.addr[ID_MT_L] = fl_take(&A, 4096);
		bt.addr[ID_MT_H] = fl_take(&A, 21);
#undef NAMED

		/* Grow the block table to its final size: fixed ids 1..10, three
		 * record blocks per entry (ent order), the Paths tree pages, four
		 * quad blocks per entry (dfs order) and the HLIndex tree pages. */
		{
			uint32_t Pp = (pplan.nleaf ? (uint32_t)pplan.nleaf - 1 : 0)
			    + (pplan.nleaf > 1 ? 1 : 0);
			uint32_t Hp = (hplan.nleaf ? (uint32_t)hplan.nleaf - 1 : 0)
			    + (hplan.nleaf > 1 ? 1 : 0);
			uint32_t NB = 10u + 7u * n + Pp + Hp;
			uint32_t oldn = bt.nblocks;
			if (NB > bt.nblocks) {
				bt.nblocks = NB;
				bt.addr = realloc(bt.addr,
				    (bt.nblocks + 1) * sizeof(uint32_t));
				bt.size = realloc(bt.size,
				    (bt.nblocks + 1) * sizeof(uint32_t));
				bt.data = realloc(bt.data,
				    (bt.nblocks + 1) * sizeof(unsigned char *));
				memset(bt.addr + oldn + 1, 0,
				    (bt.nblocks - oldn) * sizeof(uint32_t));
				memset(bt.size + oldn + 1, 0,
				    (bt.nblocks - oldn) * sizeof(uint32_t));
				memset(bt.data + oldn + 1, 0,
				    (bt.nblocks - oldn) * sizeof(unsigned char *));
			}
		}

		g_paths_nl = (uint32_t)pplan.nleaf;
		g_hl_nl = (uint32_t)hplan.nleaf;
		g_paths_leaf[0] = ID_PATHS_L;
		g_hl_leaf[0] = ID_HL_L;
		{
			uint32_t bump = 11, sp = 0, sh = 0;
			for (i = 0; i < n; i++) {
				ent *e = &ents[i];
				e->prblk = bump++;
				e->fileblk = bump++;
				e->piiblk = bump++;
				bt.size[e->prblk] = e->recsize;
				bt.size[e->fileblk] =
				    4 + (uint32_t)strlen(e->name) + 1;
				bt.size[e->piiblk] = 8;
				bt.addr[e->prblk] = fl_take(&A, bt.size[e->prblk]);
				bt.addr[e->fileblk] =
				    fl_take(&A, bt.size[e->fileblk]);
				bt.addr[e->piiblk] = fl_take(&A, 8);
				/* Tree pages get their ids here (interleaved
				 * with the records) but are not physically
				 * allocated until after BomInfo. */
				while (sp < pplan.nsplits &&
				    pplan.splits[sp].insert == i) {
					uint32_t cid = pplan.splits[sp].newleaf;
					g_paths_leaf[cid] = bump++;
					bt.size[g_paths_leaf[cid]] = 4096;
					if (sp == 0) {
						g_paths_int = bump++;
						bt.size[g_paths_int] = 4096;
					}
					sp++;
				}
			}
			for (i = 0; i < n; i++) {
				ent *e = dorder[i];
				e->qbase = bump;
				bump += 4;
				bt.size[e->qbase + 0] = 21;
				bt.size[e->qbase + 1] = 64;
				bt.size[e->qbase + 2] = 4;
				bt.size[e->qbase + 3] = 4;
				bt.addr[e->qbase + 1] = fl_take(&A, 64);
				bt.addr[e->qbase + 0] = fl_take(&A, 21);
				bt.addr[e->qbase + 2] = fl_take(&A, 4);
				bt.addr[e->qbase + 3] = fl_take(&A, 4);
				while (sh < hplan.nsplits &&
				    hplan.splits[sh].insert == i) {
					uint32_t cid = hplan.splits[sh].newleaf;
					g_hl_leaf[cid] = bump++;
					bt.size[g_hl_leaf[cid]] = 4096;
					if (sh == 0) {
						g_hl_int = bump++;
						bt.size[g_hl_int] = 4096;
					}
					sh++;
				}
			}
		}
		fl_push(&A, info12, 12);
		bt.addr[ID_INFO] = fl_take(&A, bt.size[ID_INFO]);

		/* Tree pages are physically allocated last.  The Paths pages come
		 * first (leaves in creation order, then the interior), then space
		 * is reserved for the first index copy, then the HLIndex pages
		 * (leaves in creation order, then the interior), then space for
		 * the final index copy which the header points at. */
		for (i = 1; i < pplan.nleaf; i++)
			bt.addr[g_paths_leaf[i]] = fl_take(&A, 4096);
		if (pplan.nleaf > 1)
			bt.addr[g_paths_int] = fl_take(&A, 4096);
		{
			uint32_t *ta = malloc(sizeof(uint32_t) * (OVFL + 64));
			uint32_t *ts = malloc(sizeof(uint32_t) * (OVFL + 64));
			uint32_t nc = 0;
			if (ta == NULL || ts == NULL) {
				free(ta);
				free(ts);
				goto done;
			}
			fl_pairs(&A, ta, ts, &nc);
			free(ta);
			free(ts);
			idx_size = 4u + 8u * pool + 12u + 8u * (nc + 1);
		}
		commits[0] = A.hi;
		A.hi += idx_size;
		for (i = 1; i < hplan.nleaf; i++)
			bt.addr[g_hl_leaf[i]] = fl_take(&A, 4096);
		if (hplan.nleaf > 1)
			bt.addr[g_hl_int] = fl_take(&A, 4096);
		commits[1] = A.hi;
		A.hi += idx_size;
	}
	*out_len = A.hi;
	out = calloc(1, A.hi);
	if (out == NULL)
		goto done;

	/* ---- render: vars first (later reused by blocks), then blocks ---- */
	for (i = 0; i < 5; i++) {
		unsigned char vb[60];
		memset(vb, 0, sizeof(vb));
		put_var(vb, i + 1, ids5, nm5);
		memcpy(out + var_addr[i], vb, varlen[i]);
	}
	put32(out + info12, 1);
	put32(out + info12 + 4, 1);
	put32(out + info12 + 8, 0);

	/* fixed tree blocks.  Paths is keyed by (parent,name) and inserted in
	 * ent order; HLIndex is keyed by breadth-first rank and inserted in dfs
	 * order.  Layout plans were built up front in pass 1. */
	{
		unsigned char h[21];
		uint32_t *leafblk = NULL;
		size_t j;

		/* ---- Paths ---- */
		leafblk = calloc(pplan.nleaf ? pplan.nleaf : 1, sizeof(uint32_t));
		if (leafblk == NULL)
			goto done;
		for (j = 0; j < pplan.nleaf; j++)
			leafblk[pplan.chain[j]] = g_paths_leaf[pplan.chain[j]];
		memcpy(h, "tree", 4);
		put32(h + 4, 1);
		put32(h + 8, g_paths_int ? g_paths_int
		    : (pplan.nleaf ? leafblk[pplan.chain[0]] : ID_PATHS_L));
		put32(h + 12, 0x1000);
		put32(h + 16, (uint32_t)n);
		h[20] = 0;
		memcpy(out + bt.addr[ID_PATHS_H], h, 21);
		for (j = 0; j < pplan.nleaf; j++) {
			uint32_t cid = pplan.chain[j];
			unsigned char *lbuf = calloc(1, 4096);
			uint32_t nxt = (j + 1 < pplan.nleaf)
			    ? leafblk[pplan.chain[j + 1]] : 0;
			uint32_t prv = (j > 0)
			    ? leafblk[pplan.chain[j - 1]] : 0;
			size_t sst = pplan.leaf[cid].start;
			size_t cst = pplan.leaf[cid].count;
			put16(lbuf, 1);
			put16(lbuf + 2, (uint16_t)cst);
			put32(lbuf + 4, nxt);
			put32(lbuf + 8, prv);
			for (i = 0; (size_t)i < cst; i++) {
				size_t rnk = (size_t)pplan.sorted[sst + i];
				put32(lbuf + 12 + 8 * i, ents[rnk].piiblk);
				put32(lbuf + 16 + 8 * i, ents[rnk].fileblk);
			}
			memcpy(out + bt.addr[leafblk[cid]], lbuf, 4096);
			free(lbuf);
		}
		if (pplan.nleaf > 1 && g_paths_int) {
			unsigned char *nbuf = calloc(1, 4096);
			put16(nbuf, 0);
			put16(nbuf + 2, (uint16_t)(pplan.nleaf - 1));
			put32(nbuf + 4, 0);
			put32(nbuf + 8, 0);
			for (j = 0; j + 1 < pplan.nleaf; j++) {
				uint32_t cid = pplan.chain[j];
				size_t lastr = pplan.leaf[cid].start +
				    pplan.leaf[cid].count - 1;
				uint32_t el = (uint32_t)pplan.sorted[lastr];
				put32(nbuf + 12 + 8 * j, leafblk[cid]);
				put32(nbuf + 16 + 8 * j, ents[el].fileblk);
			}
			{
				uint32_t cl = pplan.chain[pplan.nleaf - 1];
				put32(nbuf + 12 + 8 * (pplan.nleaf - 1),
				    leafblk[cl]);
				put32(nbuf + 16 + 8 * (pplan.nleaf - 1), 0);
			}
			memcpy(out + bt.addr[g_paths_int], nbuf, 4096);
			free(nbuf);
		}
		free(leafblk);

		/* ---- HLIndex ---- */
		leafblk = calloc(hplan.nleaf ? hplan.nleaf : 1, sizeof(uint32_t));
		if (leafblk == NULL)
			goto done;
		for (j = 0; j < hplan.nleaf; j++)
			leafblk[hplan.chain[j]] = g_hl_leaf[hplan.chain[j]];
		memcpy(h, "tree", 4);
		put32(h + 4, 1);
		put32(h + 8, g_hl_int ? g_hl_int
		    : (hplan.nleaf ? leafblk[hplan.chain[0]] : ID_HL_L));
		put32(h + 12, 0x1000);
		put32(h + 16, (uint32_t)n);
		h[20] = 0;
		memcpy(out + bt.addr[ID_HL_H], h, 21);
		for (j = 0; j < hplan.nleaf; j++) {
			uint32_t cid = hplan.chain[j];
			unsigned char *lbuf = calloc(1, 4096);
			uint32_t nxt = (j + 1 < hplan.nleaf)
			    ? leafblk[hplan.chain[j + 1]] : 0;
			uint32_t prv = (j > 0)
			    ? leafblk[hplan.chain[j - 1]] : 0;
			size_t sst = hplan.leaf[cid].start;
			size_t cst = hplan.leaf[cid].count;
			put16(lbuf, 1);
			put16(lbuf + 2, (uint16_t)cst);
			put32(lbuf + 4, nxt);
			put32(lbuf + 8, prv);
			for (i = 0; (size_t)i < cst; i++) {
				size_t rnk = (size_t)hplan.sorted[sst + i];
				put32(lbuf + 12 + 8 * i, ents[rnk].qbase + 3);
				put32(lbuf + 16 + 8 * i, ents[rnk].qbase + 2);
			}
			memcpy(out + bt.addr[leafblk[cid]], lbuf, 4096);
			free(lbuf);
		}
		if (hplan.nleaf > 1 && g_hl_int) {
			unsigned char *nbuf = calloc(1, 4096);
			put16(nbuf, 0);
			put16(nbuf + 2, (uint16_t)(hplan.nleaf - 1));
			put32(nbuf + 4, 0);
			put32(nbuf + 8, 0);
			for (j = 0; j + 1 < hplan.nleaf; j++) {
				uint32_t cid = hplan.chain[j];
				size_t lastr = hplan.leaf[cid].start +
				    hplan.leaf[cid].count - 1;
				uint32_t el = (uint32_t)hplan.sorted[lastr];
				put32(nbuf + 12 + 8 * j, leafblk[cid]);
				put32(nbuf + 16 + 8 * j, ents[el].qbase + 2);
			}
			{
				uint32_t cl = hplan.chain[hplan.nleaf - 1];
				put32(nbuf + 12 + 8 * (hplan.nleaf - 1),
				    leafblk[cl]);
				put32(nbuf + 16 + 8 * (hplan.nleaf - 1), 0);
			}
			memcpy(out + bt.addr[g_hl_int], nbuf, 4096);
			free(nbuf);
		}
		free(leafblk);

		put32(h + 8, ID_SZ_L);
		put32(h + 12, 0x80);
		put32(h + 16, 0);
		memcpy(out + bt.addr[ID_SZ_H], h, 21);
		{
			unsigned char *l = calloc(1, 128);
			put16(l, 1);
			memcpy(out + bt.addr[ID_SZ_L], l, 128);
			free(l);
		}
		put32(h + 8, ID_MT_L);
		put32(h + 12, 0x1000);
		put32(h + 16, 0);
		memcpy(out + bt.addr[ID_MT_H], h, 21);
		{
			unsigned char *l = calloc(1, 4096);
			put16(l, 1);
			memcpy(out + bt.addr[ID_MT_L], l, 4096);
			free(l);
		}
		memset(h, 0, sizeof(h));
		put32(h, 1);
		put32(h + 4, 7);
		put32(h + 8, 0);
		h[12] = 0;
		memcpy(out + bt.addr[ID_VIX], h, 13);
	}	/* BomInfo */
	{
		unsigned char *bi = calloc(12 + 16 * ninfo, 1);
		uint32_t plainsize = 0, fsum = 0;
		if (bi == NULL)
			goto done;
		for (i = 0; i < n; i++) {
			ent *e = &ents[i];
			if (e->macho)
				continue;
			if (!e->sidecar && e->type == 1)
				fsum += e->size;
			if (e->size > plainsize)
				plainsize = e->size;
		}
		if (fsum > plainsize)
			plainsize = fsum;
		put32(bi, 1);
		put32(bi + 4, n + 1);
		put32(bi + 8, ninfo);
		put32(bi + 12, 0);
		put32(bi + 16, 0);
		put32(bi + 20, plainsize);
		put32(bi + 24, 0);
		for (i = 0; i < narch; i++) {
			put32(bi + 28 + 16 * i, arcp[i]);
			put32(bi + 36 + 16 * i, (uint32_t)arsz[i]);
		}
		memcpy(out + bt.addr[ID_INFO], bi, 12 + 16 * ninfo);
		free(bi);
	}

	/* per-path records, names and path-info (pid order) */
	for (i = 0; i < n; i++) {
		ent *e = &ents[i];
		if (e->type == 1 && e->macho) {
			unsigned char rec[32];
			int k;
			memset(rec, 0, sizeof(rec));
			rec[0] = 1;
			rec[1] = 1;
			put16(rec + 2, e->macho == 2 ? 0x200f : 0x100f);
			put16(rec + 4, (uint16_t)e->mode);
			put32(rec + 14, e->mtime);
			put32(rec + 18, e->size);
			rec[22] = 1;
			put32(rec + 23, e->cksum);
			rec[27] = 1;
			put32(rec + 28, (uint32_t)e->nsl);
			memcpy(out + bt.addr[e->prblk], rec, 32);
			for (k = 0; k < e->nsl; k++) {
				unsigned char *p = out + bt.addr[e->prblk] +
				    32 + 16 * k;
				put32(p + 0, e->sl[k].cputype);
				put32(p + 4, e->sl[k].subtype);
				put32(p + 8, e->sl[k].len);
				put32(p + 12, e->sl[k].cksum);
			}
		} else {
			unsigned char rec[35];
			memset(rec, 0, sizeof(rec));
			rec[0] = (unsigned char)e->type;
			rec[1] = 1;
			put16(rec + 2, e->sidecar ? 1 : 0xf);
			put16(rec + 4, (uint16_t)e->mode);
			put32(rec + 14, e->sidecar ? 0 : e->mtime);
			put32(rec + 18, e->sidecar ? 0 : e->size);
			rec[22] = 1;
			put32(rec + 23, e->sidecar ? 0 : e->cksum);
			put32(rec + 27, e->sidecar ? 0 : e->lnklen);
			memcpy(out + bt.addr[e->prblk], rec, 31);
			if (e->type == 3 && e->target != NULL)
				memcpy(out + bt.addr[e->prblk] + 31,
				    e->target, e->lnklen);
		}
		put32(out + bt.addr[e->fileblk], e->parent);
		memcpy(out + bt.addr[e->fileblk] + 4, e->name,
		    strlen(e->name) + 1);
		put32(out + bt.addr[e->piiblk], e->pid);
		put32(out + bt.addr[e->piiblk] + 4, e->prblk);
	}

	/* quad trees (sorted-path order) */
	for (i = 0; i < n; i++) {
		ent *e = dorder[i];
		unsigned char lf[64];
		memset(lf, 0, sizeof(lf));
		put16(lf, 1);
		memcpy(out + bt.addr[e->qbase + 1], lf, 64);
		memcpy(out + bt.addr[e->qbase + 0], "tree", 4);
		put32(out + bt.addr[e->qbase + 0] + 4, 1);
		put32(out + bt.addr[e->qbase + 0] + 8, e->qbase + 1);
		put32(out + bt.addr[e->qbase + 0] + 12, 0x40);
		put32(out + bt.addr[e->qbase + 0] + 16, 0);
		out[bt.addr[e->qbase + 0] + 20] = 0;
		put32(out + bt.addr[e->qbase + 2], e->prblk);
		put32(out + bt.addr[e->qbase + 3], e->qbase);
	}

	/* index written twice, trailer reflects the live free list each time */
	{
		uint32_t *fa = malloc(sizeof(uint32_t) * (OVFL + 64));
		uint32_t *fs = malloc(sizeof(uint32_t) * (OVFL + 64));
		int c;
		if (fa == NULL || fs == NULL) {
			free(fa);
			free(fs);
			goto done;
		}
		for (c = 0; c < 2; c++) {
			uint32_t off = commits[c];
			uint32_t np, k, t = off + 4 + 8 * pool;
			fl_pairs(&A, fa, fs, &np);
			put32(out + off, pool);
			for (i = 0; i < pool; i++) {
				uint32_t a = (i >= 1 && i <= bt.nblocks) ? bt.addr[i] : 0;
				uint32_t s = (i >= 1 && i <= bt.nblocks) ? bt.size[i] : 0;
				/* The first index copy is built before the HLIndex
				 * tree pages are allocated, so its entries for them
				 * are still zero. */
				if (c == 0) {
					uint32_t h;
					for (h = 1; h < g_hl_nl; h++)
						if (i == g_hl_leaf[h]) { a = 0; s = 0; }
					if (g_hl_int && i == g_hl_int) { a = 0; s = 0; }
				}
				put32(out + off + 4 + 8 * i, a);
				put32(out + off + 4 + 8 * i + 4, s);
			}
			put32(out + t, np);
			for (k = 0; k < np; k++) {
				put32(out + t + 4 + 8 * k, fa[k]);
				put32(out + t + 4 + 8 * k + 4, fs[k]);
			}
			if (c == 0)
				fl_push(&A, commits[0], idx_size);
		}
		free(fa);
		free(fs);
	}

	/* header */
	memcpy(out, "BOMStore", 8);
	put32(out + 8, 1);
	put32(out + 12, bt.nblocks);
	put32(out + 16, commits[1]);
	put32(out + 20, idx_size);
	put32(out + 24, var_addr[4]);
	put32(out + 28, 60);

done:
	bom_btree_plan_free(&pplan);
	bom_btree_plan_free(&hplan);
	for (i = 0; i < n; i++) {
		free(ents[i].name);
		free(ents[i].rel);
		free(ents[i].target);
	}
	free(ents);
	free(dorder);
	free(porder);
	if (bt.data != NULL) {
		for (i = 0; i <= bt.nblocks; i++)
			free(bt.data[i]);
		free(bt.data);
	}
	free(bt.addr);
	free(bt.size);
	fl_destroy(&A);
	if (g_fail) {
		free(out);
		out = NULL;
	}
	return out;
}
