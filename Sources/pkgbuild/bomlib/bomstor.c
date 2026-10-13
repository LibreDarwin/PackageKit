#include "bomstor.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define PAGE_SIZE 4096
#define BM_FIXED_START 0x200
#define BM_MAXBUCKET 0x10000
#define BM_TREE_PAD 0x1000

static void *zalloc(size_t n)
{
	void *p = malloc(n);
	if (p)
		memset(p, 0, n);
	return p;
}

static void fl_free(bomfreelist_t *fl, uint32_t addr, uint32_t size)
{
	bomfreelist_entry_t *e;
	if (size == 0)
		return;
	e = (bomfreelist_entry_t *)zalloc(sizeof(*e));
	e->addr = addr;
	e->size = size;
	if (size >= BM_MAXBUCKET) {
		e->next = fl->overflow;
		fl->overflow = e;
		return;
	}
	if (size >= fl->bucket_count) {
		uint32_t old = fl->bucket_count;
		uint32_t newc = size + 1;
		if (newc < 32)
			newc = 32;
		if (newc > BM_MAXBUCKET)
			newc = BM_MAXBUCKET;
		if (size >= newc && size < BM_MAXBUCKET)
			newc = size + 1;
		if (newc > BM_MAXBUCKET)
			newc = BM_MAXBUCKET;
		fl->buckets = (bomfreelist_entry_t **)realloc(fl->buckets, newc * sizeof(*fl->buckets));
		if (old < newc)
			memset(fl->buckets + old, 0, (newc - old) * sizeof(*fl->buckets));
		fl->bucket_count = newc;
	}
	if (size < fl->bucket_count) {
		e->next = fl->buckets[size];
		fl->buckets[size] = e;
	} else {
		e->next = fl->overflow;
		fl->overflow = e;
	}
}

static bomfreelist_t *fl_create(uint32_t base, uint32_t size)
{
	bomfreelist_t *fl = (bomfreelist_t *)zalloc(sizeof(*fl));
	fl->bucket_count = 32;
	fl->buckets = (bomfreelist_entry_t **)zalloc(fl->bucket_count * sizeof(*fl->buckets));
	fl->overflow = NULL;
	if (size > 0)
		fl_free(fl, base, size);
	return fl;
}

static uint32_t fl_alloc(bomfreelist_t *fl, uint32_t n)
{
	bomfreelist_entry_t *e;
	if (n < fl->bucket_count && fl->buckets[n]) {
		e = fl->buckets[n];
		fl->buckets[n] = e->next;
		uint32_t a = e->addr;
		free(e);
		return a;
	}
	for (uint32_t s = n + 1; s < fl->bucket_count; s++) {
		if (fl->buckets[s]) {
			e = fl->buckets[s];
			fl->buckets[s] = e->next;
			uint32_t a = e->addr;
			uint32_t rem = e->size - n;
			free(e);
			if (rem)
				fl_free(fl, a + n, rem);
			return a;
		}
	}
	if (fl->overflow) {
		bomfreelist_entry_t *prev = NULL;
		bomfreelist_entry_t *cur = fl->overflow;
		bomfreelist_entry_t *best = NULL;
		bomfreelist_entry_t *bestprev = NULL;
		while (cur) {
			if (cur->size >= n) {
				if (best == NULL || cur->size < best->size) {
					best = cur;
					bestprev = prev;
				}
			}
			prev = cur;
			cur = cur->next;
		}
		if (best) {
			if (bestprev)
				bestprev->next = best->next;
			else
				fl->overflow = best->next;
			uint32_t a = best->addr;
			uint32_t rem = best->size - n;
			free(best);
			if (rem)
				fl_free(fl, a + n, rem);
			return a;
		}
	}
	return 0;
}

bomstorage_t *bomstorage_create(int fd, uint32_t initial_map, uint32_t block_table_capacity)
{
	bomstorage_t *s = (bomstorage_t *)zalloc(sizeof(*s));
	s->fd = fd;
	s->file_size = 0;
	s->map_size = initial_map;
	if (s->map_size < PAGE_SIZE)
		s->map_size = PAGE_SIZE;
	s->map_base = mmap(NULL, s->map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	s->nvblocks = 0;
	s->block_table_cap = block_table_capacity ? block_table_capacity : 4096;
	s->block_table = (bomblock_t *)zalloc(sizeof(bomblock_t) * s->block_table_cap);
	s->block_table_bytes = sizeof(bomblock_t) * s->block_table_cap;
	s->freelist = fl_create(BM_FIXED_START, s->map_size - BM_FIXED_START);
	s->vars_off = 0;
	s->vars_len = 0;
	s->dirty = 1;
	return s;
}

void bomstorage_destroy(bomstorage_t *s)
{
	if (!s)
		return;
	if (s->map_base)
		munmap(s->map_base, s->map_size);
	free(s->block_table);
	free(s);
}

uint32_t bomstorage_new_block(bomstorage_t *s)
{
	uint32_t id = s->nvblocks + 1;
	if (id >= s->block_table_cap) {
		uint32_t nc = s->block_table_cap * 2;
		if (nc < id + 1)
			nc = id + 1;
		s->block_table = (bomblock_t *)realloc(s->block_table, sizeof(bomblock_t) * nc);
		memset(s->block_table + s->block_table_cap, 0, sizeof(bomblock_t) * (nc - s->block_table_cap));
		s->block_table_cap = nc;
	}
	s->nvblocks = id;
	s->block_table[id].free = 0;
	s->block_table[id].addr = 0;
	s->block_table[id].size = 0;
	return id;
}

uint32_t bomstorage_new_named_block(bomstorage_t *s, const char *name, uint32_t type)
{
	(void)name;
	(void)type;
	return bomstorage_new_block(s);
}

void bomstorage_free_block(bomstorage_t *s, uint32_t id)
{
	if (id < 1 || id > s->nvblocks)
		return;
	if (s->block_table[id].addr != 0 && s->block_table[id].size != 0 && !s->block_table[id].free) {
		fl_free(s->freelist, s->block_table[id].addr, s->block_table[id].size);
		s->block_table[id].free = 1;
	}
}

void bomstorage_set_block(bomstorage_t *s, uint32_t id, const void *data, uint32_t size)
{
	if (id < 1 || id > s->nvblocks)
		return;
	if (s->block_table[id].addr != 0 && s->block_table[id].size != size && !s->block_table[id].free) {
		fl_free(s->freelist, s->block_table[id].addr, s->block_table[id].size);
		s->block_table[id].free = 1;
		s->block_table[id].addr = 0;
		s->block_table[id].size = 0;
	}
	if (s->block_table[id].addr == 0 || s->block_table[id].free) {
		uint32_t a = fl_alloc(s->freelist, size);
		if (a == 0) {
			uint32_t need = s->map_size + size + PAGE_SIZE * 16;
			uint32_t newm = (need + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
			void *nm = mmap(NULL, newm, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
			memcpy(nm, s->map_base, s->map_size);
			munmap(s->map_base, s->map_size);
			s->map_base = nm;
			fl_free(s->freelist, s->map_size, newm - s->map_size);
			s->map_size = newm;
			a = fl_alloc(s->freelist, size);
		}
		s->block_table[id].addr = a;
		s->block_table[id].size = size;
		s->block_table[id].free = 0;
	}
	memcpy((char *)s->map_base + s->block_table[id].addr, data, size);
}

uint32_t bomstorage_block_count(bomstorage_t *s)
{
	return s->nvblocks;
}

const bomblock_t *bomstorage_get_block(bomstorage_t *s, uint32_t id)
{
	if (id < 1 || id > s->nvblocks)
		return NULL;
	return &s->block_table[id];
}

void bomstorage_commit(bomstorage_t *s)
{
	(void)s;
}

void bomstorage_flush(bomstorage_t *s, const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return;
	(void)s;
	close(fd);
}
