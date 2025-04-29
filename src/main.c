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
bool arena_find_consecutive(const void* start_address, const void* end_address, uintptr_t* border);
bool arena_find_block(const void* start_address, const void* end_address, size_t min_size_request, uintptr_t* found_start, uintptr_t* found_end);
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

bool
arena_find_consecutive(
    const void* start_address,
    const void* end_address,
    uintptr_t* border
)
{
    if (start_address >= end_address)
        return false;

    uintptr_t next_block_start = *(uintptr_t*)start_address;
    byte_t in_use = *(byte_t*)((uintptr_t)start_address + sizeof(uintptr_t));

    if (in_use)
      return false;

    in_use = *(byte_t*)(next_block_start + sizeof(uintptr_t));
    while (!in_use)
    {
        next_block_start = *(uintptr_t*)next_block_start;

        if (next_block_start == (uintptr_t)NULL ||
            next_block_start >= (uintptr_t)end_address)
            break;

        in_use = *(byte_t*)(next_block_start + sizeof(uintptr_t));
    }

    if (next_block_start == (uintptr_t)NULL ||
        next_block_start >= (uintptr_t)end_address)
        next_block_start = (uintptr_t)end_address;

    *border = next_block_start;
    return true;
}

bool
arena_find_block(
    const void* start_address, const void* end_address,
    size_t min_size_request,
    uintptr_t* found_start, uintptr_t* found_end
)
{
    const void* current_block_start = start_address;

    while (1)
    {
        if (current_block_start == NULL || 
            current_block_start >= end_address)
            break;

        uintptr_t next_block_addr = *(uintptr_t*)current_block_start;
    
        byte_t in_use = *(byte_t*)((uintptr_t)current_block_start + sizeof(uintptr_t));
        
        // if this block is currently is use, continue to the next one
        if (in_use)
        {
            current_block_start = (const void*)next_block_addr;
            continue;
        }

        if (next_block_addr == (uintptr_t)NULL)
        {
            if ((uintptr_t)current_block_start + min_size_request > (uintptr_t)end_address)
                return false;

            *found_start = (uintptr_t)current_block_start;
            *found_end   = (uintptr_t)end_address;
            return true;
        }

        ptrdiff_t block_size = next_block_addr - (uintptr_t)current_block_start;
        if ((size_t)block_size >= min_size_request)
        {
            *found_start = (uintptr_t)current_block_start;
            *found_end   = next_block_addr;
            return true;
        }

        if (!arena_find_consecutive(current_block_start, end_address, &next_block_addr))
        {
            current_block_start = (const void*)next_block_addr;
            continue;
        }

        // Situation where we got to the end of the mapped memory
        if (next_block_addr == (uintptr_t)NULL ||
            next_block_addr == (uintptr_t)end_address)
        {
            ptrdiff_t total_mem = (uintptr_t)end_address - (uintptr_t)current_block_start;
            if ((size_t)total_mem < min_size_request)
                return false;

            *found_start = (uintptr_t)current_block_start;
            *found_end   = (uintptr_t)end_address;
            return true;
        }

        // Situation where the total size of consecutive blocks is enough
        block_size = next_block_addr - (uintptr_t)current_block_start;
        if ((uintptr_t)block_size >= min_size_request)
        {
            *found_start = (uintptr_t)current_block_start;
            *found_end   = next_block_addr;
            return true;
        }
        
        
        current_block_start = (const void*)next_block_addr;
    }

    return false;
}

void* arena_malloc(size_t size)
{
    uintptr_t start = 0;
    uintptr_t end   = 0;
    size_t real_size = size + sizeof(uintptr_t) + sizeof(byte_t);
    
    bool found = arena_find_block(
        arena_start_addr,
        (void*)((uintptr_t)arena_start_addr + arena_size),
        real_size,
        &start, &end);

    if (!found)
        return NULL;

    
    void* calculated_block_end = (void*)(start + real_size);
    ptrdiff_t available = end - (uintptr_t)calculated_block_end;

    if (available >= (int)(sizeof(uintptr_t) + sizeof(byte_t) +  sizeof(byte_t)))
    {
        *(uintptr_t*)calculated_block_end = end;
        *(byte_t*)((uintptr_t)calculated_block_end + sizeof(uintptr_t)) = (byte_t)0;
        *(uintptr_t*)(start) = (uintptr_t)calculated_block_end;
    }
    else
    {
        *(uintptr_t*)(start) = end;
    }

    *(byte_t*)((uintptr_t)start + sizeof(uintptr_t)) = (byte_t)1;

    return (void*)((uintptr_t)start + sizeof(uintptr_t) + sizeof(byte_t));
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

int main6(void)
{
    byte_t* mem = NULL;
      
    int pages = arena_prepare(500000);

    printf("Mapped %d pages\n", pages);
    printf("Start address: %p\n\n", arena_start_addr);

    if (pages == 0)
        return EXIT_FAILURE;

    fgetc(stdin);

    size_t allocated = arena_size - 9;
    mem = arena_malloc(allocated);

    if (mem == NULL)
    {
        arena_clear();
        return EXIT_FAILURE;
    }

    for (size_t i = 0; i < allocated; ++i)
        mem[i] = 1;
    
    fgetc(stdin);

    arena_clear();

    fgetc(stdin);
    return EXIT_SUCCESS;
}

int main(void)
{
    char* mem = NULL;
    char* mem2 = NULL;
    char* mem3 = NULL;

    int pages = arena_prepare(299999);

    printf("Mapped %d pages\n", pages);
    printf("Start address: %p\n\n", arena_start_addr);

    if (pages == 0)
        return EXIT_FAILURE;

    mem = arena_malloc(10);
    mem2 = arena_malloc(90);
    arena_free(mem);
    mem3 = arena_malloc(60);

    uintptr_t start = 0;
    uintptr_t end = 0;
    if (arena_find_block(arena_start_addr, (void*)((uintptr_t)arena_start_addr + arena_size), 10, &start, &end))
    {
        printf("arena_find_block():\n");
        printf("Start: %p\n", (void*)start);
        if (end != (uintptr_t)NULL)
        {
            printf("End:   %p\n", (void*)end);
            printf("gotten-size: %ld\n", (ptrdiff_t)(end - start));
        }

        printf("\n");
    }
    else
    {
        printf("Failed to find block!\n");
    }
    
    mem = arena_malloc(10);
    arena_free(mem2);
    mem2 = arena_malloc(90);

    printf("Mem-start 1: %p\n", mem);
    if (mem != NULL)
    {
        printf("Block-start: %p\n", get_block_start(mem));
        printf("Next-block:  %p\n", next_block_start(mem));
        printf("Block-size:  %ld\n", get_block_size(mem));
    }

    printf("\n");

    printf("Mem-start 2: %p\n", mem2);
    if (mem2 != NULL)
    {
        printf("Block-start: %p\n", get_block_start(mem2));
        printf("In-use:      %d\n", *(byte_t*)((uintptr_t)mem2 - sizeof(byte_t)));
        printf("Next-block:  %p\n", next_block_start(mem2));
        printf("Block-size:  %ld\n", get_block_size(mem2));
    }

    printf("\n");

    printf("Mem-start 3: %p\n", mem3);
    if (mem3 != NULL)
    {
        printf("Block-start: %p\n", get_block_start(mem3));
        printf("In-use:      %d\n", *(byte_t*)((uintptr_t)mem3 - sizeof(byte_t)));
        printf("Next-block:  %p\n", next_block_start(mem3));
        printf("Block-size:  %ld\n", get_block_size(mem3));
    }

    fgetc(stdin);

    arena_clear();

    return EXIT_SUCCESS;
}

int main4(void)
{
    int pages = arena_prepare(1);
    printf("Mapped %d pages\n", pages);   

    char* mem = (char*)arena_malloc(arena_size - (9 + 11));
    char* mem2 = (char*)arena_malloc(2);
    // char* mem2 = NULL;


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
        printf("In-use:      %d\n", *(byte_t*)((uintptr_t)mem2 - sizeof(byte_t)));
        printf("Next-block:  %p\n", next_block_start(mem2));
        printf("Block-size:  %ld\n", get_block_size(mem2));
    }

    return EXIT_SUCCESS;
}

int main3(void)
{
    int pages = arena_prepare(1);

    printf("Mapped %d pages\n", pages);



    char* mem = (char*)arena_malloc(arena_size - (9 + 11));
    arena_free(mem);
    uintptr_t start, end;
    if (arena_find_block(arena_start_addr, (void*)((uintptr_t)arena_start_addr + arena_size), arena_size*2, &start, &end))
    {
        printf("arena_find_block():\n");
        printf("Start: %p\n", (void*)start);
        if (end != (uintptr_t)NULL)
        {
            printf("End:   %p\n", (void*)end);
            printf("gotten-size: %ld\n", (ptrdiff_t)(end - start));
        }

        printf("\n");
    }
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
        printf("In-use:      %d\n", *(byte_t*)((uintptr_t)mem2 - sizeof(byte_t)));
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
