#pragma once
#include "Utils.h"

LPVOID ReadFileContents(LPCSTR lpFilePath, SIZE_T* OutContentSize);
BOOL WriteFileContents(LPCSTR lpFilePath, LPCVOID FileContents, SIZE_T SizeOfContents);