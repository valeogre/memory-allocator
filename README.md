Memory Allocator: Overview
This project implements a minimalistic memory allocator that manually manages virtual memory by providing basic memory allocation functions (malloc(), calloc(), realloc(), and free()). The allocator uses low-level system calls (brk(), mmap(), munmap()) to allocate and free memory, focusing on efficient memory reuse, alignment, and minimizing fragmentation.

Objectives:
Implement memory allocation functions using system calls.
Learn how to manage memory using blocks and improve performance by reducing fragmentation.
Accommodate with syscalls like brk(), mmap(), and munmap() for memory management.
Implement memory reuse, block coalescing, and splitting for better memory efficiency.
Key Features:
os_malloc(size_t size):

Allocates size bytes using brk() or mmap().
For sizes less than MMAP_THRESHOLD, uses brk().
Allocates blocks aligned to 8 bytes.
os_calloc(size_t nmemb, size_t size):

Allocates memory for nmemb elements of size bytes each.
Initializes the allocated memory to zero.
os_realloc(void *ptr, size_t size):

Changes the size of the memory block.
If shrinking, truncates; if growing, attempts to expand the current block or reallocates.
os_free(void *ptr):

Frees previously allocated memory, marking it as free and available for reuse.
Memory Management Techniques:
Memory Alignment: All allocated memory is aligned to 8 bytes for efficiency.
Block Reuse: Free blocks are marked for reuse and can be split or coalesced to reduce fragmentation.
Block Coalescing: Merges adjacent free blocks to create larger available chunks.
Split Block: Large blocks are split into smaller chunks if the remaining space is sufficient.
Best Fit Allocation: Allocates memory from the best-fitting free block to minimize wasted space.
Heap Preallocation:
A chunk of memory (e.g., 128 KB) is preallocated when the heap is first used, reducing the need for repeated brk() syscalls for small allocations.
This allocator aims to efficiently manage memory while reducing fragmentation, making it suitable for systems with limited resources.
