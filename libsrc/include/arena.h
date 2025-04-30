#ifndef ARENA_H__
#define ARENA_H__

#include <stdbool.h>

typedef char byte_t;

static void* arena_start_addr = NULL;
static size_t arena_size = 0;

int arena_prepare(int page_count);
int arena_clean();


void* arena_malloc(size_t size);
void arena_free(void* addr);



#endif // ARENA_H__
