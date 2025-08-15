// msgbox.c
#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Optional auto-run on load:
        Sleep(3000);
        MessageBoxA(NULL, "dll loaded reflectively", "Info", MB_OK);
        OutputDebugStringA("dll loaded reflectively (debug)\n");
        printf("dll loaded reflectively\n");
        Sleep(3000);
    }
    return TRUE;
}
