// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include "block_meta.h"

#define DOAMNE_AJUTA 888
#define PAGE_SIZE (4096)
#define MMAP_THRESHOLD (PAGE_SIZE * 32)
#define ALIGNMENT 8
#define META_SIZE sizeof(struct block_meta)

struct block_meta *global_base;

size_t align(size_t size)
{
	return ((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1);
}

void *get_payload(struct block_meta *block)
{
	return (void *)((char *)block + META_SIZE);
}

struct block_meta *get_block_ptr(void *ptr)
{
	return (struct block_meta *)((char *)ptr - sizeof(struct block_meta));
}

struct block_meta *request_space(struct block_meta *last, size_t size)
{
	if (size < MMAP_THRESHOLD) {
		struct block_meta *block = sbrk(size + META_SIZE);

	DIE(block == NULL, "sbrk failed\n");

	if (block == (void *)-1)
		return NULL; // sbrk failed

	if (last) // NULL on first request.
		last->next = block;

	block->size = size;
	block->next = NULL;
	block->prev = last;
	block->status = 0;
	return block;
	}
}

void coalesce(void)
{
	struct block_meta *block = global_base;

	while (block && block->next) {
		if ((block->status == STATUS_FREE) && (block->next->status == STATUS_FREE)) {
			block->size += block->next->size + META_SIZE;
			block->next = block->next->next;
			if (block->next)
				block->next->prev = block;
		} else {
			block = block->next;
		}
	}
}

struct block_meta *init_base(void)
{
	if (!global_base) {
		global_base = sbrk(MMAP_THRESHOLD);
		DIE(global_base == NULL, "sbrk failed\n");

		global_base->size = MMAP_THRESHOLD - META_SIZE;
		global_base->status = STATUS_FREE;
		global_base->next = NULL;
		global_base->prev = NULL;
	}

	return global_base;
}

struct block_meta *locate_free_block(size_t req_size)
{
	coalesce();
	struct block_meta *curr_block = global_base;

	while (curr_block) {
		if (curr_block->status == STATUS_FREE && curr_block->size >= req_size) {
			if (curr_block->size >= req_size + META_SIZE + ALIGNMENT) {
				struct block_meta *new_free_block = (struct block_meta *)((char *)curr_block + META_SIZE + req_size);

				new_free_block->size = curr_block->size - req_size - META_SIZE;
				new_free_block->status = STATUS_FREE;
				new_free_block->next = curr_block->next;
				new_free_block->prev = curr_block;

				curr_block->size = req_size;
				curr_block->status = STATUS_ALLOC;
				curr_block->next = new_free_block;

				if (new_free_block->next)
					new_free_block->next->prev = new_free_block;
				} else {
					curr_block->status = STATUS_ALLOC;
			}
			return curr_block;
		}
		curr_block = curr_block->next;
	}
	return NULL;
}

struct block_meta *expand_memory(size_t req_size, struct block_meta *last_block)
{
	struct block_meta *new_block = sbrk(req_size + META_SIZE);

	DIE(new_block == NULL, "sbrk failed\n");

	new_block->size = req_size;
	new_block->status = STATUS_ALLOC;
	new_block->prev = last_block;
	new_block->next = NULL;

	if (last_block)
		last_block->next = new_block;

	return new_block;
}

struct block_meta *locate_or_expand(size_t req_size)
{
	req_size = align(req_size);
	global_base = init_base();

	struct block_meta *free_block = locate_free_block(req_size);

	if (free_block)
		return free_block;

	struct block_meta *last_block = global_base;

	while (last_block && last_block->next)
		last_block = last_block->next;

	return expand_memory(req_size, last_block);
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	if (size <= 0)
		return NULL;

	size = align(size);

	struct block_meta *block;

	if (size < MMAP_THRESHOLD) {
		block = locate_or_expand(size);
		if (!block)
			return NULL;
	} else {
		block = (void *)syscall(9, NULL, size + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(block == MAP_FAILED, "mmap failed\n");

		block->size = size;
		block->status = STATUS_MAPPED;
		block->prev = NULL;
		block->next = NULL;
	}

	return get_payload(block);
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *ptr_to_block = get_block_ptr(ptr);

	if (!ptr_to_block)
		return;

	if (ptr_to_block->status == STATUS_MAPPED) {
		struct block_meta *prev_block = ptr_to_block->prev;
		struct block_meta *next_block = ptr_to_block->next;

		ptr_to_block->status = STATUS_FREE;

		if (!prev_block && !next_block)
			global_base = NULL;

		if (prev_block)
			prev_block->next = next_block;

		if (next_block)
			next_block->prev = prev_block;

		munmap(ptr_to_block, ptr_to_block->size + META_SIZE);
	} else {
		ptr_to_block->status = STATUS_FREE;
	}
	coalesce();
}


void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	if ((nmemb <= 0) || (size <= 0))
		return NULL;
	size_t total_size = nmemb * size;
	void *block = os_malloc(total_size);

	memset(block, 0, total_size);
	return block;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	if (!ptr)
		return os_malloc(size);

	struct block_meta *block = get_block_ptr(ptr);

	if (block->size >= size)
		return ptr;

	void *new_ptr = os_malloc(size);

	if (new_ptr) {
		memcpy(new_ptr, ptr, block->size);
		os_free(ptr);
	}
	return new_ptr;
}
