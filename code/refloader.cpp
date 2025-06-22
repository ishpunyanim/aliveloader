#include <winnt.h>
#include <stdio.h>
#include <stdint.h>

typedef enum _LoaderStatus {
    LoaderSuccess,
    LoaderFailed,
    LoaderBadFormat
} LoaderStatus;

For contextual information that loader will need
typedef struct _loader_ctx {
    void *p;
    size_t size;
} loader_ctx;

LoaderStatus
validate_dos_header(const unsigned char* buff, unint32_t size) {
    if(buff == NULL || size < sizeof(IMAGE_DOS_HEADER)) return LoaderBadFormat;
    if(buff[0] != 'M' || buff[1] != 'Z') return LoaderBadFormat;

    // Using uintptr_t to perform safety checks during pointer arithmetic operations
    // NOTE: uintptr_t can also overflow, to be more secure only use offsets
    uintptr_t base = (uintptr_t)buff;
    if(base + ((const IMAGE_DOS_HEADER*)buff)->e_lfanew > (base + size)) return LoaderBadFormat;

    return LoaderSuccess;
}

LoaderStatus
reflective_loadlibrary(loader_ctx* ctx, const void* buffer, unint32_t size) {
    LoaderStatus status = LoaderSuccess;
    unsigned char* cbuffer = (unsigned char*)buffer;
    
    if(validate_dos_header(cbuffer, size) == LoaderFailed) {
        return LoaderFailed;
    }

    return status;
}
