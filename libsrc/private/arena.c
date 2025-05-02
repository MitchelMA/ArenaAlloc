#include <arena.h>

#include <string.h>
#include <unistd.h>
#include <sys/mman.h>


typedef char byte_t;
static arena_instance_t static_arena;

// MACROS

#define META_DATA_SIZE (sizeof(uintptr_t) + sizeof(byte_t))

#define GET_USE_OFFSET_(MEM_PTR) ((uintptr_t)(MEM_PTR) + sizeof(uintptr_t))
#define READ_IN_USE(MEM_PTR) (*(byte_t*)(GET_USE_OFFSET_(MEM_PTR)))
#define SET_IN_USE(MEM_PTR, VAL) (*(byte_t*)(GET_USE_OFFSET_(MEM_PTR)) = (byte_t)(VAL))

#define GET_NEXT_BLOCK(MEM_PTR) (*(uintptr_t*)(MEM_PTR))
#define SET_NEXT_BLOCK(MEM_PTR, NEXT_PTR) (GET_NEXT_BLOCK(MEM_PTR) = (uintptr_t)(NEXT_PTR))

#define GET_USER_SPACE_OFFSET_(MEM_PTR) ((uintptr_t)(MEM_PTR) + META_DATA_SIZE)
#define GET_USER_PTR(MEM_PTR) (void*)GET_USER_SPACE_OFFSET_(MEM_PTR)

#define GET_ARENA_SPACE_OFFSET_(USER_PTR) ((uintptr_t)(USER_PTR) - META_DATA_SIZE)
#define GET_ARENA_PTR(USER_PTR) (void*)GET_ARENA_SPACE_OFFSET_(USER_PTR)

// END MACROS

// Local declerations

static bool find_consecutive_(const void* start_address, const void* end_address, uintptr_t* border);
static bool find_block_(const void* start_address, const void* end_address, size_t min_size_request, uintptr_t* found_start, uintptr_t* found_end);

static void* find_mem_start_(arena_instance_t* instance, void* addr);
static void* next_block_start_(void* addr);

// End local declerations

// Non-static

size_t arena_prepare(arena_instance_t* instance, size_t page_count)
{
    if (instance->start_addr != NULL)
        return 0;

    instance->size = page_count * getpagesize();
    instance->start_addr = (byte_t*)mmap(NULL, instance->size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

    if (instance->start_addr == NULL || instance->start_addr == MAP_FAILED)
        return 0;

    return page_count;
}

int arena_clean(arena_instance_t* instance)
{
    if (instance->start_addr == NULL || instance->start_addr == MAP_FAILED)
        return -1;

    return munmap((void*)instance->start_addr, instance->size);
}

void* arena_malloc(arena_instance_t* instance, size_t size)
{
    uintptr_t start = 0;
    uintptr_t end   = 0;
    size_t real_size = size + META_DATA_SIZE;
    
    bool found = find_block_(
        instance->start_addr,
        (void*)((uintptr_t)instance->start_addr + instance->size),
        real_size,
        &start, &end);

    if (!found)
        return NULL;
    
    void* calculated_block_end = (void*)(start + real_size);
    ptrdiff_t available = end - (uintptr_t)calculated_block_end;

    if (available >= (int64_t)(META_DATA_SIZE + sizeof(byte_t)))
    {
        SET_NEXT_BLOCK(calculated_block_end, (void*)end);
        SET_NEXT_BLOCK((void*)start, calculated_block_end);
        SET_IN_USE(calculated_block_end, 0);
    }
    else
    {
        SET_NEXT_BLOCK((void*)start, (void*)end);
    }

    SET_IN_USE((void*)start, 1);
    return GET_USER_PTR((void*)start);
}

void* arena_realloc(arena_instance_t* instance, void* addr, size_t size)
{
    size_t current_size = (size_t)arena_get_block_size(addr);
    size_t real_request_size = size + META_DATA_SIZE;

    // Do nothing when there's no change in size
    if (size == current_size)
        return addr;

    // Shrink within the current block
    if (size < current_size)
    {
        uint64_t diff = current_size - size;
        // When the requested difference is smaller than the required size of meta-data + an extra byte,
        // Nothing gets done
        if (diff < META_DATA_SIZE + sizeof(byte_t))
            return addr;

        uintptr_t old_end = GET_NEXT_BLOCK(GET_ARENA_PTR(addr));
        uintptr_t new_end = old_end - diff;
        SET_NEXT_BLOCK((void*)new_end, (void*)old_end);
        SET_NEXT_BLOCK(GET_ARENA_PTR(addr), (void*)new_end);
        SET_IN_USE((void*)new_end, 0);
        return addr;
    }

    uintptr_t start = (uintptr_t)GET_ARENA_PTR(addr);

    // Try to first grow the block from it's current starting point
    uintptr_t border = 0;
    bool found = find_consecutive_(
        (const void*)GET_NEXT_BLOCK((void*)start),
        (const void*)((uintptr_t)instance->start_addr + instance->size),
        &border
    );

    if (found)
    {
        // Test the size
        size_t consecutive_size = border - start;
        size_t corrected_size = consecutive_size - META_DATA_SIZE;
        void* calculated_block_end = (void*)(start + real_request_size);
        if (corrected_size >= size)
        {
            ptrdiff_t available = border - (uintptr_t)calculated_block_end;

            if (available >= (int64_t)(META_DATA_SIZE + sizeof(byte_t)))
            {
                SET_NEXT_BLOCK((void*)start, calculated_block_end);
                SET_NEXT_BLOCK(calculated_block_end, (void*)border);
                SET_IN_USE(calculated_block_end, 0);
            }
            else
            {
                SET_NEXT_BLOCK((void*)start, (void*)border);
            }

            return addr;
        }
    }

    // When growing from the current address failed
    SET_IN_USE((void*)start, 0);

    uintptr_t new_start = 0;
    uintptr_t new_end = 0;
    found = find_block_(
        instance->start_addr,
        (const void*)((uintptr_t)instance->start_addr + instance->size),
        real_request_size,
        &new_start,
        &new_end
    );

    // Couldn't find a block of the requested size
    if (!found)
    {
        SET_IN_USE((void*)start, 1);
        return NULL;
    }

    // Move the old memory data to the new block
    memmove(GET_USER_PTR((void*)new_start), addr, current_size);

    void* calculated_block_end = (void*)(new_start + real_request_size);
    ptrdiff_t available = new_end - (uintptr_t)calculated_block_end;

    if (available >= (int64_t)(META_DATA_SIZE + sizeof(byte_t)))
    {
        SET_NEXT_BLOCK((void*)new_start, calculated_block_end);
        SET_NEXT_BLOCK(calculated_block_end, (void*)new_end);
        SET_IN_USE(calculated_block_end, 0);
    }
    else
    {
        SET_NEXT_BLOCK((void*)new_start, (void*)new_end);
    }

    SET_IN_USE((void*)new_start, 1);

    return GET_USER_PTR((void*)new_start);
}

void arena_free(arena_instance_t* instance, void* addr)
{
    void* mem_start = find_mem_start_(instance, addr);
    if (!arena_block_in_use(mem_start))
        return;

    SET_IN_USE(GET_ARENA_PTR(mem_start), 0);
}

// Static

size_t arena_static_prepare(size_t page_count)
{
    return arena_prepare(&static_arena, page_count);
}

int arena_static_clean()
{
    return arena_clean(&static_arena);
}

void* arena_static_malloc(size_t size)
{
    return arena_malloc(&static_arena, size);
}

void* arena_static_realloc(void* addr, size_t size)
{
    return arena_realloc(&static_arena, addr, size);
}

void arena_static_free(void* addr)
{
    arena_free(&static_arena, addr);
}

// Utility

ptrdiff_t arena_get_block_size(void* addr)
{
    return (uintptr_t)next_block_start_(addr) - (uintptr_t)addr;
}

bool arena_block_in_use(void* addr)
{
    return READ_IN_USE(GET_ARENA_PTR(addr)) == 1;
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

    uintptr_t next_block_start = GET_NEXT_BLOCK(start_address);
    byte_t in_use              = READ_IN_USE(start_address);

    if (in_use)
      return false;

    in_use = READ_IN_USE(next_block_start);
    while (!in_use)
    {
        next_block_start = GET_NEXT_BLOCK(next_block_start);

        if (next_block_start == (uintptr_t)NULL ||
            next_block_start >= (uintptr_t)end_address)
            break;

        in_use = READ_IN_USE(next_block_start);
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

        uintptr_t next_block_addr = GET_NEXT_BLOCK(current_block_start);
        byte_t in_use             = READ_IN_USE(current_block_start);
        
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

void* find_mem_start_(arena_instance_t* instance, void* addr)
{
    void* start = instance->start_addr;
    void* end = (void*)((uintptr_t)instance->start_addr + instance->size);
    void* next = (void*)GET_NEXT_BLOCK(start);

    while(1)
    {
        if (next == NULL ||
            (uintptr_t)next >= (uintptr_t)end)
            break;

        bool within_range = (uintptr_t)addr > (uintptr_t)start && (uintptr_t)addr < (uintptr_t)next;
        if (within_range)
            break;

        start = next;
        next = (void*)GET_NEXT_BLOCK(start);
    }

    return GET_USER_PTR(start);
}

void* next_block_start_(void* addr)
{
    return (void*)GET_NEXT_BLOCK(GET_ARENA_PTR(addr));
}

// End local definitions
