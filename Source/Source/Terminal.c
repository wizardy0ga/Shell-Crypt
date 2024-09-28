#pragma once
#include "../Include/Terminal.h"

/*
    Description: Print the encryption key in C/C++ syntax.

    Parameter: PBYTE pKey: A pointer to the key to print
    Parameter: SIZE_T SizeOfKey: The size of the key pointed to by pKey
*/
VOID PrintKeyC(PBYTE pKey, SIZE_T SizeOfKey) {
    printf("\n\nchar Key[%lld] = {", SizeOfKey);
    for (int i = 0; i < SizeOfKey; i++) {
        if ((i % 16) == 0 || i == 0) {
            printf("\n\t0x%0.2X,", pKey[i]);
        }
        else if (i == (SizeOfKey - 1)) {
            printf("0x%0.2X\n};", pKey[i]);
        }
        else if ((i % 16) > 0) {
            printf("0x%0.2X,", pKey[i]);
        }

    }
}

/*
    Description: Print the shellcode in C/C++ syntax

    Parameter: PBYTE pShellcode: A pointer to the shellcode to print
    Parameter: SIZE_T ShellcodeSize: The size of the shellcode to print
*/
VOID PrintShellcodeC(PBYTE pShellcode, SIZE_T ShellcodeSize) {
    printf("\n\nchar shellcode[%lld] = {", ShellcodeSize);
    for (int i = 0; i < ShellcodeSize; i++) {
        if ((i % 16) == 0 || i == 0) {
            printf("\n\t0x%0.2X,", pShellcode[i]);
        }
        else if ((i % 16) > 0 && i != (ShellcodeSize - 1)) {
            printf("0x%0.2X,", pShellcode[i]);
        }
        else {
            printf("0x%0.2X\n};", pShellcode[i]);
        }
    }
}

/*
    Description: Print the shellcode using powershell syntax.

    Notes: This is dead code, not currently used.

VOID PrintShellcodePowerShell(PBYTE pShellcode, SIZE_T ShellcodeSize) {
    printf("$Shellcode = ");
    for (int i = 0; i < ShellcodeSize; i++) {
        if (i == ShellcodeSize - 1) {
            printf("0x%0.2X", pShellcode[i]);
        }
        else {
            printf("0x%0.2X, ", pShellcode[i]);
        }
    }
    printf("\n");
}
*/