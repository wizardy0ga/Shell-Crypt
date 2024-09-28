#include "../Include/IO.h"

/*
    Description: Reads the contents of a file. Returns the contents of the file as a pointer.

    Parameter: LPCSTR lpFilePath: The path of the file to read
    Parameter: SIZE_T* OutContentSize: A pointer to write the size of the file contents to
*/
LPVOID ReadFileContents(LPCSTR lpFilePath, SIZE_T* OutContentSize) {

    HANDLE hHeap         = NULL,
           hFile         = NULL;
    DWORD  dwFileSize    = 0,
           dwBytesRead   = 0;
    BOOL   ContentsRead  = FALSE;
    LPVOID pFileContents = NULL;

    // Get a handle to the heap. 
    if (!(hHeap = GetProcessHeap())) {
        apierror("GetProcessHeap"); return NULL;
    }

    // Get a handle to the file to read.
    hFile = CreateFileA(lpFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        switch (GetLastError()) {
        case ERROR_FILE_NOT_FOUND:
            error("%s does not exist.", lpFilePath); goto Cleanup;
        default:
            apierror("CreateFileA"); goto Cleanup;
        }
    }

    // Get the file size, allocate memory on the heap == file size & read file
    // into memory
    if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
        apierror("GetFileSize"); goto Cleanup;
    }
    if (!(pFileContents = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwFileSize))) {
        apierror("HeapAlloc"); goto Cleanup;
    }
    if (!ReadFile(hFile, pFileContents, dwFileSize, &dwBytesRead, NULL)) {
        apierror("ReadFile"); goto Cleanup;
    }

    ContentsRead = TRUE;
    if (dwFileSize != dwBytesRead) {
        error("GetFileSize returned %ld bytes but only %ld bytes were read.", dwFileSize, dwBytesRead); goto Cleanup;
    }

Cleanup:
    if (hFile) {
        CloseHandle(hFile);
    }
    if (pFileContents && ContentsRead == FALSE) {
        HeapFree(hHeap, 0, pFileContents); pFileContents = NULL;
    }
    if (ContentsRead) {
        *OutContentSize = dwFileSize;
    }
    if (hHeap) {
        CloseHandle(hHeap);
    }
    return pFileContents;
}

/*
    Description: Write data to a file. File will always be created / overwritten.

    Parameter: LPCSTR lpFilePath:     The path of the file to write to
    Parameter: LPCVOID FileContents:  The contents to write to the file
    Parameter: SIZE_T SizeOfContents: The size of the file contents to write
*/
BOOL WriteFileContents(LPCSTR lpFilePath, LPCVOID FileContents, SIZE_T SizeOfContents) {

    HANDLE hFile          = NULL;
    DWORD  dwBytesWritten = 0;
    BOOL   ContentWritten = FALSE;

    // Get a handle to the file, write the data to the file.
    if ((hFile = CreateFileA(lpFilePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
        apierror("CreateFileA"); return FALSE;
    }
    if (WriteFile(hFile, FileContents, (DWORD)SizeOfContents, &dwBytesWritten, NULL) && (dwBytesWritten == SizeOfContents)) {
        ContentWritten = TRUE;
    }
    else {
        error("Failed to write payload to %s. %lld bytes were given to function, %ld bytes were written to file.", lpFilePath, SizeOfContents, dwBytesWritten);
    }

    // Cleanup & return.
    hFile ? CloseHandle(hFile) : FALSE;
    return ContentWritten;
}