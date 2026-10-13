#ifndef BOMSTOR_H
#define BOMSTOR_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bomfreelist_entry {
	struct bomfreelist_entry *next;
	uint32_t addr;
	uint32_t size;
} bomfreelist_entry_t;

typedef struct bomfreelist {
	bomfreelist_entry_t **buckets;
	uint32_t bucket_count;
	bomfreelist_entry_t *overflow;
} bomfreelist_t;

typedef struct bomblock {
	uint32_t addr;
	uint32_t size;
	int free;
} bomblock_t;

typedef struct bomstorage {
	int fd;
	uint32_t file_size;
	void *map_base;
	uint32_t map_size;
	uint32_t nvblocks;
	uint32_t toc_off;
	uint32_t toc_size;
	uint32_t block_table_cap;
	bomblock_t *block_table;
	uint32_t block_table_bytes;
	bomfreelist_t *freelist;
	uint32_t vars_off;
	uint32_t vars_len;
	int dirty;
} bomstorage_t;

bomstorage_t *bomstorage_create(int fd, uint32_t initial_map, uint32_t block_table_capacity);
void bomstorage_destroy(bomstorage_t *s);
void bomstorage_set_block(bomstorage_t *s, uint32_t id, const void *data, uint32_t size);
uint32_t bomstorage_new_block(bomstorage_t *s);
uint32_t bomstorage_new_named_block(bomstorage_t *s, const char *name, uint32_t type);
void bomstorage_free_block(bomstorage_t *s, uint32_t id);
void bomstorage_commit(bomstorage_t *s);
uint32_t bomstorage_block_count(bomstorage_t *s);
const bomblock_t *bomstorage_get_block(bomstorage_t *s, uint32_t id);
void bomstorage_flush(bomstorage_t *s, const char *path);

#ifdef __cplusplus
}
#endif
#endif
