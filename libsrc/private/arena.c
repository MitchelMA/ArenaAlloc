#include <arena.h>

#include <unistd.h>
#include <sys/mman.h>

typedef char byte_t;

static void* arena_start_addr = NULL;
static size_t arena_size = 0;

// Local declerations

static bool find_consecutive_(const void* start_address, const void* end_address, uintptr_t* border);
static bool find_block_(const void* start_address, const void* end_address, size_t min_size_request, uintptr_t* found_start, uintptr_t* found_end);

static void* find_mem_start_(void* addr);
static void* next_block_start_(void* addr);

// End local declerations

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

int arena_clean()
{
    if (arena_start_addr == NULL || arena_start_addr == MAP_FAILED)
        return -1;

    return munmap((void*)arena_start_addr, arena_size);
}

void* arena_malloc(size_t size)
{
    uintptr_t start = 0;
    uintptr_t end   = 0;
    size_t real_size = size + sizeof(uintptr_t) + sizeof(byte_t);
    
    bool found = find_block_(
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
    void* mem_start = find_mem_start_(addr);
    if (!arena_block_in_use(mem_start))
        return;

    *(byte_t*)((uintptr_t)mem_start - sizeof(byte_t)) = 0;
}

bool arena_block_in_use(void* addr)
{
    return *(((byte_t*)addr) - 1) == 1;
}

ptrdiff_t arena_get_block_size(void* addr)
{
    return (uintptr_t)next_block_start_(addr) - (uintptr_t)addr;
}

void* next_block_start_(void* addr)
{
    return (void*) *(uintptr_t*)((uintptr_t)addr - sizeof(byte_t) - sizeof(uintptr_t));
}

// local definitions

bool
find_consecutive_(
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
find_block_(
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

        if (!find_consecutive_(current_block_start, end_address, &next_block_addr))
        {
            current_block_start = (const void*)next_block_addr;
            continue;
        }

        // Situation where we got to the end of the mapped memory
        if (next_block_addr == (uintptr_t)end_address)
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

void* find_mem_start_(void* addr)
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

// End local definitions
