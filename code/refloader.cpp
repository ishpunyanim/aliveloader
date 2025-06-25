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


static LoaderStatus
copy_sections(unsigned char* dest,
              uint32_t dest_size,
              const unsigned char* src,
              uint32_t src_size,
              const IMAGE_NT_HEADERS* nt) {
    uint16_t sec_count = 0;
    const IMAGE_SECTION_HEADER *sec = (IMAGE_SECTION_HEADER*)(&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    for(uint16_t i = 0; i < sec_count; i++) {
        unsigned char *sec_va = dest + sec[i].VirtualAddress;
        const unsigned char *sec_offset = src + sec[i].PointerToRawData;
        uint32_t sec_size = sec[i].SizeOfRawData;
        memcpy(sec_va, sec_offset, sec_size);
    }

    return LoaderSuccess;
}

// Headers must be copied first, they contain layout info (e.g., section RVA, sizes)
// In order to correctly copy section data and relocate from the source buffer.
static LoaderStatus
copy_headers(unsigned char* dest,
             uint32_t dest_size,
             const unsigned char* src,
             uint32_t src_size,
             const IMAGE_NT_HEADERS* nt) {
    if(dest == NULL || src == NULL || nt == NULL) return LoaderInvalid;

    uint32_t hdr_size = 0;
    if((hdr_size = nt->OptionalHeader.SizeOfHeaders) == 0) return LoaderBadFormat;
    if(hdr_size > dest_size || hdr_size > src_size) return LoaderBadFormat;
    
    memcpy(dest, src, hdr_size);

    return LoaderSuccess;
}

static LoaderStatus
copy_image(unsigned char* dest,
           uint32_t dest_size,
           unsigned char* src,
           uint32_t src_size,
           const IMAGE_NT_HEADERS* nt) {
    LoaderStatus status = LoaderSuccess;
    
    status = copy_headers(dest, dest_size, src, src_size, nt);
    if(status != LoaderSuccess) return status;
    
    return copy_sections(dest, dest_size, src, src_size, nt);
}

static LoaderStatus
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

    // Allocating space
    if((nb_size = nt->OptionalHeader.SizeOfImage) == 0) return LoaderBadFormat;

    new_buffer = (unsigned char*)VirtualAlloc(NULL,
                                              nb_size,
                                              MEM_COMMIT|MEM_RESERVE,
                                              PAGE_EXECUTE_READWRITE);
    if(new_buffer == NULL) return LoaderNoMem;

    // Copy data
    status = copy_image(new_buffer, nb_size, cbuffer, size, nt);
    if(status != LoaderSuccess) goto cleanup; 

cleanup:
    if(status != LoaderSuccess) {
        VirtualFree(new_buffer, 0, MEM_RELEASE);
    }
    
    return status;
}

int main() {
    return 0;
}
