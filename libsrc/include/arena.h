#ifndef ARENA_H__
#define ARENA_H__

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct arena_instance
{
    void* start_addr;
    size_t size;
} arena_instance_t;

// Non-static

size_t arena_prepare(arena_instance_t* instance, size_t page_count);
size_t arena_prepare_file(arena_instance_t* instance, size_t page_count, const char* file_name);
int arena_clean(arena_instance_t* instance);

void arena_reset(arena_instance_t* instance);
void arena_hard_reset(arena_instance_t* instance);

void* arena_malloc(arena_instance_t* instance, size_t size);
void* arena_realloc(arena_instance_t* instance, void* addr, size_t size);
void arena_free(arena_instance_t* instance, void* addr);

// Static

size_t arena_static_prepare(size_t page_count);
size_t arena_static_prepare_file(size_t page_count, const char* file_name);
int arena_static_clean();

void arena_static_reset();
void arena_static_hard_reset();

void* arena_static_malloc(size_t size);
void* arena_static_realloc(void* addr, size_t size);
void  arena_static_free(void* addr);

// Utility

ptrdiff_t arena_get_block_size(void* addr);
bool arena_block_in_use(void* addr);


#endif // ARENA_H__
