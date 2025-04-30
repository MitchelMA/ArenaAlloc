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

int arena_prepare(arena_instance_t* instance, int page_count);
int arena_clean(arena_instance_t* instance);

void* arena_malloc(arena_instance_t* instance, size_t size);
void arena_free(arena_instance_t* instance, void* addr);

// Static

int arena_static_prepare(int page_count);
int arena_static_clean();

void* arena_static_malloc(size_t size);
void  arena_static_free(void* addr);

// Utility

ptrdiff_t arena_get_block_size(void* addr);
bool arena_block_in_use(void* addr);


#endif // ARENA_H__
