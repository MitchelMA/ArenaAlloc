#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdbool.h>

typedef char byte_t;

static void* arena_start_addr = NULL;
static size_t arena_size = 0;

int arena_prepare(int page_count);
int arena_clear();
void* arena_malloc(size_t size);
void arena_free(void* addr);
bool block_in_use(void* addr);
void* find_mem_start(void* addr);
void* get_block_start(void* addr);
void* next_block_start(void* addr);
ptrdiff_t get_block_size(void* addr);


int arena_prepare(int page_count)
{
    if (arena_start_addr != NULL)
        return 0;

    size_t byte_count = page_count * getpagesize();
    arena_size = byte_count;
    arena_start_addr = (byte_t*)mmap(NULL, byte_count, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

    if (arena_start_addr == NULL || arena_start_addr == MAP_FAILED)
        return 0;

    return page_count;
}

int arena_clear()
{
    if (arena_start_addr == NULL || arena_start_addr == MAP_FAILED)
        return -1;

    return munmap((void*)arena_start_addr, arena_size);
}

void* arena_malloc(size_t size)
{
    // Finding the first empty block
    void* current_block_start = arena_start_addr;
    void* known_next_block_start = NULL;
    while(1)
    {
        uintptr_t addr_value = *((uintptr_t*)current_block_start);
        byte_t in_use = *((byte_t*)current_block_start + sizeof(uintptr_t));

        if (addr_value == 0)
            break;

        // check available size
        if (!in_use)
        {
            ptrdiff_t available_size = (addr_value - (uintptr_t)current_block_start) - sizeof(uintptr_t) - sizeof(byte_t);
            if (available_size >= size)
            {
                known_next_block_start = (void*)addr_value;
                break;
            } 

            // Check for following blocks that are freed
            void* next_block = (void*)addr_value;
            byte_t next_in_use = *((byte_t*)next_block + sizeof(uintptr_t));
            
            while (!next_in_use)
            {
                next_block = (void*)*((uintptr_t*)next_block);

                if (next_block == NULL)
                    break;

                next_in_use = *((byte_t*)next_block + sizeof(uintptr_t));
            }

            if (next_block == NULL)
                break;

            known_next_block_start = next_block;
            available_size = ((uintptr_t)next_block - (uintptr_t)current_block_start) - sizeof(uintptr_t) - sizeof(byte_t);
            if (available_size >= size)
                break;
        }

        current_block_start = (void*)addr_value;
    }

    // Checking if the allocation would be within the bounds of the allocated space of the arena 
    ptrdiff_t relative_offset = ((uintptr_t)current_block_start + sizeof(uintptr_t) + sizeof(byte_t)) - (uintptr_t)arena_start_addr;
    if (relative_offset + size > arena_size)
        return NULL;

    // writing in the starting address of the next block
    void* block_end = (void*)((uintptr_t)current_block_start + sizeof(uintptr_t) + sizeof(byte_t) + size);
    
    if (known_next_block_start == NULL)
    {
        *(uintptr_t*)(current_block_start) = (uintptr_t)block_end;
    }
    else
    {
        // check first if we can split the block
        ptrdiff_t available = (uintptr_t)known_next_block_start - (uintptr_t)block_end;
        if (available >= (sizeof(uintptr_t) + sizeof(byte_t) +  sizeof(byte_t)))
        {
            // write into after the current block to keep the blocks correct
            *(uintptr_t*)block_end = (uintptr_t)known_next_block_start;
            // and mark as not in use
            *((byte_t*)block_end + sizeof(uintptr_t)) = (byte_t)0;
            // write this block-end into the first 4 bytes of the current block
            *(uintptr_t*)(current_block_start) = (uintptr_t)block_end;
        }
        else
        {
            // when not enough is available, just give the full block
            *(uintptr_t*)(current_block_start) = (uintptr_t)known_next_block_start;
        }
    }

    // marking this block as in-use
    *((byte_t*)current_block_start + sizeof(uintptr_t)) = 1;
    
    // and return the address after all the written info
    return (void*)((uintptr_t)current_block_start + sizeof(uintptr_t) + sizeof(byte_t));
}

void arena_free(void* addr)
{
    void* mem_start = find_mem_start(addr);
    if (!block_in_use(mem_start))
        return;

    *(byte_t*)((uintptr_t)mem_start - sizeof(byte_t)) = 0;
}

bool block_in_use(void* addr)
{
    return *(((byte_t*)addr) - 1) == 1;
}

void* find_mem_start(void* addr)
{
    void* start = arena_start_addr;
    void* next = (void*)*(uintptr_t*)start;

    while(1)
    {
        if (next == NULL)
            break;

        bool within_range = (uintptr_t)addr > (uintptr_t)start && (uintptr_t)addr < (uintptr_t)next;
        if (within_range)
            break;

        start = next;
        next = (void*)*(uintptr_t*)start;
    }

    return (void*)((uintptr_t)start + sizeof(uintptr_t) + sizeof(byte_t));
}

void* get_block_start(void* addr)
{
    return (void*) ((uintptr_t)addr - sizeof(byte_t) - sizeof(uintptr_t));
}

void* next_block_start(void* addr)
{
    return (void*) *(uintptr_t*)((uintptr_t)addr - sizeof(byte_t) - sizeof(uintptr_t));
}

ptrdiff_t get_block_size(void* addr)
{
    return (uintptr_t)next_block_start(addr) - (uintptr_t)addr;
}

int main(void)
{
    int pages = arena_prepare(200000);

    printf("Mapped %d pages\n", pages);

    char* mem = (char*)arena_malloc(arena_size - (9 + 11));
    char* mem2 = (char*)arena_malloc(2);
    arena_free(mem);
    mem = arena_malloc(arena_size - (9 + 11));

    printf("Mem-start:   %p\n", mem);
    if (mem != NULL)
    {
        printf("Block-start: %p\n", get_block_start(mem));
        printf("Next-block:  %p\n", next_block_start(mem));
        printf("Block-size:  %ld\n", get_block_size(mem));
    }

    printf("\n");

    printf("Mem-start:   %p\n", mem2);
    if (mem2 != NULL)
    {
        printf("Block-start: %p\n", get_block_start(mem2));
        printf("Next-block:  %p\n", next_block_start(mem2));
        printf("Block-size:  %ld\n", get_block_size(mem2));
    }


    fgetc(stdin);

    
    arena_clear();

    return EXIT_SUCCESS;
}

int main2(void)
{
    int pages = arena_prepare(2);

    printf("Hello, World!\n");
    printf("Mapped %d pages\n", pages);
    printf("start addr: %p\n", arena_start_addr);
    printf("Arena size: %lu\n\n", arena_size);

    char* mem = (char*)arena_malloc(100);
    mem[0] = (byte_t)1;
    mem[1] = (byte_t)3;

    char* mem2 = (char*)arena_malloc(10);
    arena_free(mem);
    char* mem3 = (char*)arena_malloc(3);
    char* mem4 = (char*)arena_malloc(4);

    printf("mem start: %p\n", (void*)mem);
    printf("block-start: %p\n", get_block_start(mem));
    printf("mem in-use: %d\n", block_in_use((void*)mem));
    printf("next-block: %p\n", next_block_start(mem));
    printf("block-size: %ld\n\n", get_block_size(mem));

    printf("mem start: %p : %p\n", (void*)mem2, find_mem_start(mem2 + 2));
    printf("block-start: %p\n", get_block_start(mem2));
    printf("mem in-use: %d\n", block_in_use((void*)mem2));
    printf("next-block: %p\n", next_block_start(mem2));
    printf("block-size: %ld\n\n", get_block_size(mem2));

    printf("mem start: %p\n", (void*)mem3);
    printf("block-start: %p\n", get_block_start(mem3));
    printf("mem in-use: %d\n", block_in_use(mem3));
    printf("next-block: %p\n", next_block_start(mem3));
    printf("block-size: %ld\n\n", get_block_size(mem3));

    printf("mem start: %p\n", (void*)mem4);
    printf("block-start: %p\n", get_block_start(mem4));
    printf("mem in-use: %d\n", block_in_use(mem4));
    printf("next-block: %p\n", next_block_start(mem4));
    printf("block-size: %ld\n", get_block_size(mem4));

    // arena_free(mem);
    arena_free(mem2);
    arena_free(mem3);
    arena_free(mem4);

    arena_clear();
    return EXIT_SUCCESS;
}
