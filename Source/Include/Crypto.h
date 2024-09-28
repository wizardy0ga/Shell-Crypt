#include <time.h>
#include "Utils.h"

VOID Xor(PBYTE pData, SIZE_T SizeOfData, PBYTE pKey, SIZE_T SizeOfKey);
VOID CreateEncryptedKey(BYTE HintByte, SIZE_T KeySize, PBYTE* OutEncryptedKey, PBYTE* OutOriginalKey);
PBYTE EncryptKey(PBYTE pKey, SIZE_T KeySize, PBYTE* OutKeyByte);