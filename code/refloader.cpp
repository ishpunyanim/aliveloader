#ifdef _M_X64
#define _AMD64_
#define CURRENT_ARCH  IMAGE_FILE_MACHINE_AMD64
#else
#define _X86_
#define CURRENT_ARCH  IMAGE_FILE_MACHINE_I386
#endif

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

typedef enum _LoaderStatus {
    LoaderSuccess,
    LoaderFailed,
    LoaderBadFormat,
    LoaderInvalid,
    LoaderNoMem
} LoaderStatus;

// For contextual information that loader will need
typedef struct _loader_ctx {
    void *p;
    size_t size;
} loader_ctx;

LoaderStatus
validate_dos_header(const unsigned char* buff, uint32_t size) {
    if(buff == NULL || size < sizeof(IMAGE_DOS_HEADER)) return LoaderBadFormat;
    if(buff[0] != 'M' || buff[1] != 'Z') return LoaderBadFormat;

    // Using uintptr_t to perform safety checks during pointer arithmetic operations
    // NOTE: uintptr_t can also overflow, to be more secure only use offsets
    uintptr_t base = (uintptr_t)buff;
    if(base + ((const IMAGE_DOS_HEADER*)buff)->e_lfanew > (base + size)) return LoaderBadFormat;

    return LoaderSuccess;
}

LoaderStatus
reflective_loadlibrary(loader_ctx* ctx, const void* buffer, uint32_t size) {
    LoaderStatus status = LoaderSuccess;
    unsigned char* cbuffer = (unsigned char*)buffer;
    const IMAGE_NT_HEADERS* nt = NULL;
    unsigned char* new_buffer = NULL;
    uint32_t nb_size = 0;

    if(ctx == NULL) return LoaderInvalid;
    
    if(validate_dos_header(cbuffer, size) == LoaderFailed) {
        return LoaderFailed;
    }

    nt = (const IMAGE_NT_HEADERS*)(cbuffer + ((const IMAGE_DOS_HEADER*)buffer)->e_lfanew);

    if((nb_size = nt->OptionalHeader.SizeOfImage) == 0) return LoaderBadFormat;

    new_buffer = (unsigned char*)VirtualAlloc(NULL,
                      nb_size,
                      MEM_COMMIT|MEM_RESERVE,
                      PAGE_EXECUTE_READWRITE);
    if(new_buffer == NULL) return LoaderNoMem;

    // Cleanup
    if(status != LoaderSuccess) {
        VirtualFree(new_buffer, 0, MEM_RELEASE);
    }
    
    return status;
}

int main() {
    return 0;
}
