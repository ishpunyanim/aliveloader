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
#include "msgbox_dll_payload.h"

typedef enum _LoaderStatus {
    LoaderSuccess,
    LoaderFailed,
    LoaderBadFormat,
    LoaderInvalid,
    LoaderNoMem,
    LoaderNotFound
} LoaderStatus;

// For contextual information that loader will need
typedef struct _loader_ctx {
    void *p;
    size_t size;
} loader_ctx;


static
LoaderStatus handle_imports(unsigned char* image_base,
                            const IMAGE_NT_HEADERS* nt)
{
    LoaderStatus status = LoaderSuccess;
    
    const IMAGE_IMPORT_DESCRIPTOR* imp = (const IMAGE_IMPORT_DESCRIPTOR*)(image_base
                                                                          + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    const uint32_t imp_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    // We will continue processing until we hit the terminating NULL
    for(; imp->Characteristics; imp++)
    {
        const char* library_name = (const char*)(image_base + imp->Name);
        HMODULE hm = NULL;

        // We will try to load the library, if it fails, we will exit, as we can't finish loading the library.
        if((hm = LoadLibrary(library_name)) == NULL) return LoaderNotFound;

        char* func_name = NULL;
        
        // This will be the INT
        IMAGE_THUNK_DATA* orig_first_thunk = (IMAGE_THUNK_DATA*)(image_base + imp->OriginalFirstThunk);

        // This will be the IAT
        IMAGE_THUNK_DATA* first_thunk = (IMAGE_THUNK_DATA*)(image_base + imp->FirstThunk);

        for(uint32_t i = 0; orig_first_thunk[i].u1.AddressOfData; i++)
        {
            IMAGE_IMPORT_BY_NAME* by_name = NULL;
            const char* search_value = NULL;
            
            // Update first_thunk->u1.Function to point to the export
            if(orig_first_thunk[i].u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                search_value = (const char*)IMAGE_ORDINAL(orig_first_thunk[i].u1.Ordinal);
            }
            else
            {
                search_value = (const char*)((IMAGE_IMPORT_BY_NAME*)(image_base + orig_first_thunk[i].u1.AddressOfData))->Name;
            }

            if(0 == (first_thunk[i].u1.Function = (ULONG_PTR)GetProcAddress(hm, search_value)))
            {
                FreeLibrary(hm);
                return LoaderNotFound;
            }
        }
    }

    return status;
}

// Walking through the relocation table brick-by-brick.
//
// Design specifics:
// - The relocation table (usually in the .reloc section) consists of one or more IMAGE_BASE_RELOCATION blocks.
// - Each block typically describes relocations for a single 4KB memory page.
//   The VirtualAddress field in the header indicates the start of that page.
// - The entire table can span multiple file pages. It is not limited to a single page.
//   Each block only contains relocations for its associated page.
//
// Why group relocations by page instead of a simple flat list?
// - Grouping by page allows the loader to efficiently change memory page protections,
//   apply all fixups for that page at once, then restore protections.
// - This reduces overhead from repeatedly changing page permissions (e.g., from read-only
//   to writable and back), which is costly.

static LoaderStatus
relocate_image(unsigned char* image_base,
               const IMAGE_NT_HEADERS* nt)
{
    LoaderStatus status = LoaderSuccess;

    // Get the entry  for relocations
    const IMAGE_DATA_DIRECTORY* data_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    // Use the DATA_DIRECTORY RVA to get the actual section location
    const IMAGE_BASE_RELOCATION* relocs = (const IMAGE_BASE_RELOCATION*)(image_base + data_dir->VirtualAddress);

    // This will be the total size of our relocation block
    uint32_t total_size = data_dir->Size;
    
    uintptr_t delta = (uintptr_t)image_base - nt->OptionalHeader.ImageBase;

    // In this loop:
    // Track how far we've walked through the relocation section (current_size)
    // Ensure we don’t read past the section boundary (using total_size)
    // For each block:
    //   - Subtract the header size from SizeOfBlock to get the size of the relocation entries
    //   - Divide by 2 [sizeof(uint16_t)] to get the number of 16-bit entries
    //   - Step to the next block using SizeOfBlock

    for(uint32_t current_size = 0;
        current_size <= total_size;
        relocs = (const IMAGE_BASE_RELOCATION*)((const unsigned char*)relocs + relocs->SizeOfBlock),
        current_size += relocs->SizeOfBlock)
    {
        uint32_t current_block = relocs->SizeOfBlock;
        current_block -= sizeof(IMAGE_BASE_RELOCATION);

        // Each relocation entry is 2 bytes (uint16_t), using 2 directly here is safe and equivalent to sizeof(uint16_t)
        current_block /= 2;

        // Relocation entries are packed into a dynamic array of 16-bit values:
        //   relocation_entry (16 bits) = [ 4-bit type | 12-bit offset ]
        // The 12-bit offset is relative to the base address of the current 4KB page. This is sufficient to locate the fix-up target within that page.
        // The 4-bit relocation type tells the loader how to apply the delta, including data size and format.
        
        // uint16_t reloc_type = entry >> 12;
        // uint16_t reloc_offset = entry & 0xfff;

        // The relocation entries in each block point to RVAs (relative virtual addresses) within the loaded image.
        // Even though relocs was calculated using image_base to locate the relocation block itself, we must still add image_base again when calculating relocate_location.
        // That's because:
        //   - relocs->VirtualAddress gives the RVA of a 4KB page.
        //   - each entry's offset is within that page.
        //   - Together: `relocs->VirtualAddress + offset` is the RVA to fix.
        //   - To patch actual memory, we convert RVA to pointer using: image_base + RVA
        // Final formula:
        //   relocate_location = image_base + relocs->VirtualAddress + reloc_offset;
        // This ensures we're modifying the correct address in the loaded image.

        const uint16_t* entry = (uint16_t*)((unsigned char*)relocs + sizeof(*relocs));

        for(uint32_t i = 0; i < current_block; i++)
        {
            uint16_t reloc_type = entry[i] >> 12;
            uint16_t reloc_offset = entry[i] & 0xfff;

            unsigned char* relocate_location = image_base + relocs->VirtualAddress + reloc_offset;
            switch(reloc_type)
            {
                case IMAGE_REL_BASED_LOW:
                    *((uint16_t*)relocate_location) += LOWORD(delta);
                    break;
                case IMAGE_REL_BASED_HIGH:
                    *((uint16_t*)relocate_location) += HIWORD(delta);
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *((uint32_t*)relocate_location) += (int32_t)delta;
                    break;
                case IMAGE_REL_BASED_DIR64:
                    *((uint64_t*)relocate_location) += delta;
            }
        }
    }

    return status;
}

static LoaderStatus
copy_sections(unsigned char* dest,
              uint32_t dest_size,
              const unsigned char* src,
              uint32_t src_size,
              const IMAGE_NT_HEADERS* nt)
{
    uint16_t sec_count = nt->FileHeader.NumberOfSections;
    // Calculate pointer to the first IMAGE_SECTION_HEADER.
    // We start at &nt->OptionalHeader, cast to (unsigned char*) to allow byte-wise offsetting,
    // then add SizeOfOptionalHeader (in bytes) to skip over the optional header.
    // Finally, cast the result to (IMAGE_SECTION_HEADER*) to access section headers properly.
    const IMAGE_SECTION_HEADER *sec = (const IMAGE_SECTION_HEADER*)(const unsigned char*)(&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    for(uint16_t i = 0; i < sec_count; i++)
    {
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
             const IMAGE_NT_HEADERS* nt)
{
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
           const IMAGE_NT_HEADERS* nt)
{
    LoaderStatus status = LoaderSuccess;
    
    status = copy_headers(dest, dest_size, src, src_size, nt);
    if(status != LoaderSuccess) return status;
    
    return copy_sections(dest, dest_size, src, src_size, nt);
}

static LoaderStatus
validate_dos_header(const unsigned char* buff, uint32_t size)
{
    if(buff == NULL || size < sizeof(IMAGE_DOS_HEADER)) return LoaderBadFormat;
    if(buff[0] != 'M' || buff[1] != 'Z') return LoaderBadFormat;

    // Using uintptr_t to perform safety checks during pointer arithmetic operations
    // NOTE: uintptr_t can also overflow, to be more secure only use offsets
    uintptr_t base = (uintptr_t)buff;
    if(base + ((const IMAGE_DOS_HEADER*)buff)->e_lfanew > (base + size)) return LoaderBadFormat;

    return LoaderSuccess;
}

LoaderStatus
reflective_loadlibrary(loader_ctx* ctx, const void* buffer, uint32_t size)
{
    LoaderStatus status = LoaderSuccess;
    unsigned char* cbuffer = (unsigned char*)buffer;
    const IMAGE_NT_HEADERS* nt = NULL;
    unsigned char* new_buffer = NULL;
    uint32_t nb_size = 0;

    if(ctx == NULL) return LoaderInvalid;
    
    if(validate_dos_header(cbuffer, size) == LoaderFailed)
    {
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

    // Handle relocations
    status = relocate_image(new_buffer, nt);
    if(status != LoaderSuccess) goto cleanup;

    // Resolve imports
    status = handle_imports(new_buffer, nt);
    if(status != LoaderSuccess) goto cleanup;

    // Call entry point
    uintptr_t entry = (uintptr_t)new_buffer + nt->OptionalHeader.AddressOfEntryPoint;
    typedef BOOL(WINAPI *DllMainProto)(HINSTANCE, DWORD, LPVOID);
    DllMainProto entry_fn = (DllMainProto)entry;
    entry_fn((HINSTANCE)new_buffer, DLL_PROCESS_ATTACH, NULL);

    // Save to context
    ctx->p = new_buffer;
    ctx->size = nb_size;

    return LoaderSuccess;
    
cleanup:
    if(status != LoaderSuccess)
    {
        VirtualFree(new_buffer, 0, MEM_RELEASE);
    }
    
    return status;
}

int main()
{
    printf("[Loader] Loading DLL reflectively...\n");
    
    loader_ctx ctx = {0};
    LoaderStatus result = reflective_loadlibrary(&ctx, dllBytes, (uint32_t)dllSize);
    
    printf("Loader returned: %d\n", result);

    return 0;
}
