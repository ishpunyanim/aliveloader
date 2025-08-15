# Reflective PE Loader Demo

A minimal **reflective PE loader** project in C for Windows, demonstrating the basic steps involved in loading a Portable Executable (PE) image from memory.  

> ⚠️ **Note:** This project is experimental. The embedded DLL/exe demonstration is minimal and may not run fully, but it illustrates low-level concepts in PE loading, memory relocation, and import resolution.

---

## Overview

This project implements a **reflective loader** in C that manually performs the following steps:

1. **Validate PE headers** (`IMAGE_DOS_HEADER` and `IMAGE_NT_HEADERS`)
2. **Allocate memory** for the image (`VirtualAlloc`)
3. **Copy headers and sections** to the allocated memory
4. **Relocate the image** if loaded at a different base address
5. **Resolve imports** using `LoadLibrary` and `GetProcAddress`
6. **Invoke the entry point** of the loaded module

The goal is to simulate how a loader works internally, providing hands-on exposure to **Windows system programming**, **PE file structures**, and **manual memory management**.

---

## ⚙️ How It Works

1. Reads a PE file from disk or memory buffer.
2. Parses DOS + NT headers, section headers, and allocates target memory.
3. Copies each section into the appropriate virtual memory region.
4. Manually resolves imports by loading referenced DLLs and resolving function pointers.
5. Optionally performs base relocation (if image is not loaded at preferred address).
6. Transfers control to `DllMain` or the PE entry point.

## 📦 Build Instructions

```bash
git clone https://github.com/ishpunyanim/aliveloader
cd aliveloader/code
cl refloader.cpp pe.cpp /Fe:aliveloader.exe
