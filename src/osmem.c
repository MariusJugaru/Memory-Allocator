// SPDX-License-Identifier: BSD-3-Clause

#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include "osmem.h"
#include "block_meta.h"

#define MMAP_THRESHOLD		(128 * 1024)
#define METADATA_SIZE		(sizeof(struct block_meta))
#define ALIGNMENT 8
#define ALIGN(size)			(((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define ALIGNED_META		ALIGN(METADATA_SIZE)
#define PAGE_SIZE			getpagesize()

int heap_allocated;

// Declare list head
struct block_meta block_meta_head;

// Initialize list head
void block_meta_head_init(void)
{
	block_meta_head.size = 0;
	block_meta_head.status = 0;
	block_meta_head.prev = &block_meta_head;
	block_meta_head.next = &block_meta_head;
}

size_t min(size_t a, size_t b)
{
	if (a > b)
		return b;
	return a;
}

// Finding the best block
void *find_fit(size_t size)
{
	struct block_meta *ptr = block_meta_head.next;
	struct block_meta *aux = NULL;
	struct block_meta *ret_block = NULL;

	while (ptr != &block_meta_head) {
		if (ptr->status == STATUS_FREE && ptr->size >= size)
			aux = ptr;
		if (ret_block == NULL && aux != NULL)
			ret_block = aux;
		if (ret_block != NULL && aux != NULL && aux->size < ret_block->size)
			ret_block = aux;
		ptr = ptr->next;
	}

	if (ret_block != NULL)
		return ret_block;
	return NULL;
}

// Add block to the list
void add_block(struct block_meta *new_block)
{
	struct block_meta *check_block = block_meta_head.next;

	while (check_block != new_block && check_block != &block_meta_head)
		check_block = check_block->next;
	if (check_block == new_block)
		return;
	if (new_block->status == STATUS_FREE) {
		struct block_meta *pre_block;

		check_block = block_meta_head.next;
		while (check_block != &block_meta_head) {
			pre_block = check_block;
			check_block = check_block->next;

			if (check_block > new_block) {
				pre_block->next = new_block;
				new_block->next = check_block;
				new_block->prev = pre_block;
				check_block->prev = new_block;
				return;
			}
		}
	}
	new_block->next = &block_meta_head;
	new_block->prev = block_meta_head.prev;
	block_meta_head.prev->next = new_block;
	block_meta_head.prev = new_block;
}

void *alloc_mmap(size_t size)
{
	struct block_meta *new_block;
	int alloc_size = ALIGN(ALIGNED_META + size);
	void *ptr = (void *)mmap(NULL, alloc_size,  PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	DIE(ptr == (void *) -1, "error");
	new_block = (struct block_meta *)ptr;
	new_block->size = size;
	new_block->status = STATUS_MAPPED;

	// Add block in list
	add_block(new_block);
	return ptr;
}

// Prealloc size on heap
void *heap_prealloc(void)
{
	void *ptr = (void *)sbrk(MMAP_THRESHOLD);

	DIE(ptr == (void *) -1, "error");
	return ptr;
}

// First alloc with brk
void *prealloc_brk(size_t size)
{
	void *ptr = heap_prealloc();
	struct block_meta *new_block;

	new_block = (struct block_meta *)ptr;
	new_block->size = size;
	new_block->status = STATUS_ALLOC;

	add_block(new_block);

	// Split the remaining free space
	if (MMAP_THRESHOLD > ((ALIGNED_META + size) + (ALIGNED_META + sizeof(char)))) {
		new_block = (struct block_meta *)(ptr + ALIGN(ALIGNED_META + size));
		new_block->status = STATUS_FREE;
		new_block->size = MMAP_THRESHOLD - ALIGN(size + 2 * ALIGNED_META);

		add_block(new_block);
	}
	return ptr;
}

void coalesce_blocks(void)
{
	struct block_meta *block_ptr = block_meta_head.next;
	struct block_meta *aux = NULL;

	// Coalesce Blocks
	while (block_ptr != &block_meta_head) {
		if (block_ptr->status == STATUS_FREE && aux == NULL)
			aux = block_ptr; // First block
		if (block_ptr->status != STATUS_FREE)
			aux = NULL;
		if (aux != NULL && block_ptr->status == STATUS_FREE && block_ptr != aux) {
			aux->size = (size_t)((void *)block_ptr - (void *)aux) + block_ptr->size;

			aux->next = block_ptr->next;
			block_ptr->next->prev = aux;
		}

		block_ptr = block_ptr->next;
	}
}

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;
	if (block_meta_head.prev == NULL)
		block_meta_head_init();
	void *ptr;
	int alloc_size = ALIGN(size + ALIGNED_META); // block size

	// alloc mmap
	if (alloc_size >= MMAP_THRESHOLD) {
		ptr = alloc_mmap(size);

		return ptr + ALIGNED_META;
	}

	// alloc heap
	if (heap_allocated == 0) {
		heap_allocated = 1;
		ptr = prealloc_brk(size);

		// return payload
		return ptr + ALIGNED_META;
	}

	struct block_meta *block_ptr;

	// Coalesce Blocks
	coalesce_blocks();

	struct block_meta *new_block;

	// Check for fit block size
	new_block = find_fit(size);

	if (new_block == NULL) {
		// Check if last block is free
		block_ptr = block_meta_head.prev;
		while (block_ptr->status != STATUS_ALLOC && block_ptr->status != STATUS_FREE)
			block_ptr = block_ptr->prev;
		if (block_ptr->status == STATUS_ALLOC) {
			ptr = (void *)sbrk(alloc_size);

			DIE(ptr == (void *) -1, "error");
			new_block = (struct block_meta *)ptr;
			new_block->status = STATUS_ALLOC;
			new_block->size = size;
			add_block(new_block);
			return (void *)(new_block) + ALIGNED_META;
		}

		// Extend last block
		int aligned_block_size = ALIGN(block_ptr->size);

		ptr = (void *)sbrk(ALIGN(size) - aligned_block_size);

		DIE(ptr == (void *) -1, "error");
		block_ptr->size = size;
		block_ptr->status = STATUS_ALLOC;

		return (void *)(block_ptr) + ALIGNED_META;
	}
	alloc_size = size;
	size_t free_size;

	block_ptr = new_block->next;

	while (block_ptr != &block_meta_head && block_ptr->status != STATUS_ALLOC)
		block_ptr = block_ptr->next;
	if (block_ptr == &block_meta_head)
		free_size = (long)(sbrk(0) - (void *)new_block) - ALIGNED_META;
	else
		free_size = (long)((void *)block_ptr - (void *)new_block) - ALIGNED_META;
	free_size -= ALIGN(size);

	new_block->size = size;
	new_block->status = STATUS_ALLOC;

	if (free_size >= ALIGNED_META + sizeof(char)) {
		block_ptr = (struct block_meta *)((void *)(new_block) + ALIGN(ALIGNED_META + size));
		block_ptr->status = STATUS_FREE;
		block_ptr->size = free_size - ALIGNED_META;

		add_block(block_ptr);
	}

	return (void *)(new_block) + ALIGNED_META;
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;
	int ret_val;
	struct block_meta *block = (struct block_meta *)(ptr - ALIGN(METADATA_SIZE));

	if (block->status == STATUS_MAPPED) {
		block->prev->next = block->next;
		block->next->prev = block->prev;
		ret_val = munmap(block,  ALIGN(ALIGNED_META + block->size));
		DIE(ret_val == -1, "error");

		ptr = NULL;
		return;
	}

	if (block->status == STATUS_ALLOC) {
		block->status = STATUS_FREE;

		ptr = NULL;
		return;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (size == 0 || nmemb == 0)
		return NULL;
	if (block_meta_head.prev == NULL)
		block_meta_head_init();
	void *ptr;
	int alloc_size = ALIGN(size * nmemb) + ALIGNED_META; // block size

	// alloc mmap
	if (alloc_size >= PAGE_SIZE) {
		ptr = alloc_mmap(size * nmemb);
		memset(ptr + ALIGNED_META, 0, size * nmemb);

		return ptr + ALIGNED_META;
	}

	// alloc heap
	if (heap_allocated == 0) {
		heap_allocated = 1;
		ptr = prealloc_brk(size * nmemb);
		memset(ptr + ALIGNED_META, 0, size * nmemb);

		// return payload
		return ptr + ALIGNED_META;
	}

	struct block_meta *block_ptr;

	// Coalesce Blocks
	coalesce_blocks();

	struct block_meta *new_block;

	// Check for fit block size
	new_block = find_fit(size * nmemb);

	if (new_block == NULL) {
		// Check if last block is free
		block_ptr = block_meta_head.prev;
		while (block_ptr->status != STATUS_ALLOC && block_ptr->status != STATUS_FREE)
			block_ptr = block_ptr->prev;
		if (block_ptr->status == STATUS_ALLOC) {
			ptr = (void *)sbrk(alloc_size);
			memset(ptr + ALIGNED_META, 0, size * nmemb);

			DIE(ptr == (void *) -1, "error");
			new_block = (struct block_meta *)ptr;
			new_block->status = STATUS_ALLOC;
			new_block->size = size * nmemb;
			add_block(new_block);
			return (void *)(new_block) + ALIGNED_META;
		}

		// Extend last block
		int aligned_block_size = ALIGN(block_ptr->size);

		ptr = (void *)sbrk(ALIGN(size * nmemb) - aligned_block_size);
		memset((void *)(block_ptr) + ALIGNED_META, 0, size * nmemb);

		DIE(ptr == (void *) -1, "error");
		block_ptr->size = size * nmemb;

		return (void *)(block_ptr) + ALIGNED_META;
	}
	alloc_size = size * nmemb;
	size_t free_size;

	block_ptr = new_block->next;

	while (block_ptr != &block_meta_head && block_ptr->status != STATUS_ALLOC)
		block_ptr = block_ptr->next;
	if (block_ptr == &block_meta_head)
		free_size = (long)(sbrk(0) - (void *)new_block) - ALIGNED_META;
	else
		free_size = (long)((void *)block_ptr - (void *)new_block) - ALIGNED_META;
	free_size -= ALIGN(size * nmemb);

	new_block->size = size * nmemb;
	new_block->status = STATUS_ALLOC;

	if (free_size >= ALIGNED_META + sizeof(char)) {
		block_ptr = (struct block_meta *)((void *)(new_block) + ALIGN(ALIGNED_META + size * nmemb));
		block_ptr->status = STATUS_FREE;
		block_ptr->size = free_size - ALIGNED_META;

		add_block(block_ptr);
	}

	memset((void *)(new_block) + ALIGNED_META, 0, size * nmemb);
	return (void *)(new_block) + ALIGNED_META;
}

void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return os_malloc(size);
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	struct block_meta *block_ptr = (struct block_meta *)(ptr - ALIGN(METADATA_SIZE));

	if (block_ptr->status == STATUS_FREE)
		return NULL;
	if (block_meta_head.prev == NULL)
		block_meta_head_init();
	int alloc_size = ALIGN(size + ALIGNED_META); // block size
	int ptr_size = block_ptr->size;
	struct block_meta *new_block;
	void *return_ptr;
	size_t free_size;

	if (block_ptr->status == STATUS_MAPPED) {
		if (size < MMAP_THRESHOLD) {
			// alloc heap
			if (heap_allocated == 0) {
				heap_allocated = 1;
				return_ptr = prealloc_brk(size);
				memcpy(return_ptr + ALIGNED_META, ptr, size);
				os_free(ptr);

				// return payload
				return return_ptr + ALIGNED_META;
			}
			coalesce_blocks();
			return_ptr = find_fit(size);
			new_block = (struct block_meta *)return_ptr;

			if (return_ptr == NULL) {
				return_ptr = sbrk(ALIGN(size + ALIGNED_META));
				new_block = (struct block_meta *)return_ptr;
				add_block(new_block);
			} else {
				free_size = new_block->size;
				free_size -= ALIGN(size);

			if (free_size >= ALIGNED_META + sizeof(char)) {
				block_ptr = (struct block_meta *)((void *)(new_block) + ALIGN(ALIGNED_META + size));
				block_ptr->status = STATUS_FREE;
				block_ptr->size = free_size - ALIGNED_META;

				add_block(block_ptr);
				}
			}

			new_block->status = STATUS_ALLOC;
			new_block->size = size;
			memcpy(return_ptr + ALIGNED_META, ptr, min(size, ptr_size));
			os_free(ptr);

			return return_ptr + ALIGNED_META;
		}
		// alloc mmap
		return_ptr = alloc_mmap(size);
		memcpy(return_ptr + ALIGNED_META, ptr, min(size, ptr_size));
		os_free(ptr);

		return return_ptr + ALIGNED_META;
	}

	if (size > MMAP_THRESHOLD) {
		return_ptr = alloc_mmap(size);
		memcpy(return_ptr + ALIGNED_META, ptr, min(size, ptr_size));
		os_free(ptr);

		return return_ptr + ALIGNED_META;
	}

	if (block_ptr->status == STATUS_ALLOC)
		os_free(ptr);
	struct block_meta *aux = NULL;

	// make each free block have its maximum free size
	block_ptr = block_meta_head.next;
	while (block_ptr != &block_meta_head) {
		if (aux != NULL && block_ptr->status != STATUS_MAPPED)
			aux->size = (size_t)((void *)block_ptr - (void *)aux) - 32;
		if (block_ptr->status == STATUS_FREE)
			aux = block_ptr;
		else
			aux = NULL;
		block_ptr = block_ptr->next;
	}

	if (aux != NULL && block_ptr == &block_meta_head)
		aux->size = (size_t)(sbrk(0) - (void *)aux) - 32;
	block_ptr = (struct block_meta *)(ptr - ALIGN(METADATA_SIZE));
	struct block_meta *next_block = block_ptr->next;

	if (next_block == &block_meta_head && size > block_ptr->size) {
		int aligned_block_size = ALIGN(block_ptr->size);

		return_ptr = (void *)sbrk(ALIGN(size) - aligned_block_size);
		DIE(return_ptr == (void *) -1, "error");

		memcpy((void *)(block_ptr) + ALIGNED_META, ptr, min(size, ptr_size));
		block_ptr->size = size;
		block_ptr->status = STATUS_ALLOC;

		return (void *)(block_ptr) + ALIGNED_META;
	}

	while (next_block->status != STATUS_ALLOC && next_block != &block_meta_head) {
		if (next_block->status == STATUS_FREE) {
			block_ptr->size = (size_t)((void *)next_block - (void *)block_ptr) + next_block->size;

			block_ptr->next = next_block->next;
			next_block->next->prev = block_ptr;

			if (block_ptr->size >= size)
				break;
		}

		next_block = next_block->next;
	}

	if (next_block == &block_meta_head)
		block_ptr->size = (size_t)(sbrk(0) - (void *)block_ptr) - ALIGNED_META;
	if (block_ptr->size >= size) {
		new_block = block_ptr;
	} else {
		((struct block_meta *)(ptr - ALIGN(METADATA_SIZE)))->status = STATUS_ALLOC;
		coalesce_blocks();
		new_block = find_fit(size);
		((struct block_meta *)(ptr - ALIGN(METADATA_SIZE)))->status = STATUS_FREE;
	}
	if (new_block == NULL) {
		// Check if last block is free
		block_ptr = block_meta_head.prev;
		while (block_ptr->status != STATUS_ALLOC && block_ptr->status != STATUS_FREE)
			block_ptr = block_ptr->prev;
		if (block_ptr->status == STATUS_ALLOC) {
			return_ptr = (void *)sbrk(alloc_size);
			memcpy(return_ptr + ALIGNED_META, ptr, min(size, ptr_size));

			DIE(return_ptr == (void *) -1, "error");
			new_block = (struct block_meta *)return_ptr;
			new_block->status = STATUS_ALLOC;
			new_block->size = size;
			add_block(new_block);
			return (void *)(new_block) + ALIGNED_META;
		}

		new_block = block_ptr;
	}
	alloc_size = size;

	free_size = new_block->size;
	if (ALIGN(size) > free_size) {
		int aligned_block_size = ALIGN(new_block->size);

		return_ptr = (void *)sbrk(ALIGN(size) - aligned_block_size);
		memcpy((void *)new_block + ALIGNED_META, ptr, min(size, ptr_size));
		DIE(return_ptr == (void *) -1, "error");

		new_block->size = size;
		new_block->status = STATUS_ALLOC;

		return (void *)(new_block) + ALIGNED_META;
	}
	free_size -= ALIGN(size);

	new_block->size = size;
	new_block->status = STATUS_ALLOC;
	return_ptr = (void *)(new_block);
	memcpy(return_ptr + ALIGNED_META, ptr, min(size, ptr_size));

	if (free_size >= ALIGNED_META + sizeof(char)) {
		block_ptr = (struct block_meta *)((void *)(new_block) + ALIGN(ALIGNED_META + size));
		block_ptr->status = STATUS_FREE;
		block_ptr->size = free_size - ALIGNED_META;

		add_block(block_ptr);
	}

	return (void *)(new_block) + ALIGNED_META;
}
