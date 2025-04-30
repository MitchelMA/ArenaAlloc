#ifndef ARENA_H__
#define ARENA_H__

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

int arena_prepare(int page_count);
int arena_clean();

void* arena_malloc(size_t size);
void arena_free(void* addr);

bool arena_block_in_use(void* addr);
ptrdiff_t arena_get_block_size(void* addr);

#endif // ARENA_H__
