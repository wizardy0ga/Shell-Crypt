#pragma once
const char Banner[] =
"\n\n _______ __           __ __        ______                    __\n"
"|     __|  |--.-----.|  |  |______|      |.----.--.--.-----.|  |_ \n"
"|__     |     |  -__||  |  |______|   ---||   _|  |  |  _  ||   _|\n"
"|_______|__|__|_____||__|__|      |______||__| |___  |   __||____|\n"
"                                               |_____|__| v1.0.0\n"
"<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>\n\n";

const char Usage[] =
"\nDescription: \n"
"\t     Shell-Crypt is a utility for evading scantime detection. Your shellcode will be encrypted\n"
"\t     using XOR. Additionally, the XOR key will also be encrypted using a self-bruteforcing XOR algorithm.\n"
"\t     The code required for decrypting the key & shellcode will be provided by Shell-Crypt. It is up\n"
"\t     to the operator to implement this code within their own implant.\n\n"
"\t     Shell-Crypt will write the encrypted shellcode to a binary file specified in the arguments.\n"
"\t     The key will also be written to a file calld 'key.bin'. For quality of life, operators may \n"
"\t     run the shellcode & key through the decryption process & execute the shellcode locally via '-t' optional argument.\n"
"Syntax:\n"
"\t     Shell-Crypt.exe [Key Generation Command] [Input Shellcode File] [Output Shellcode File] [Optional Arguments]\n\n"
"Parameters:\n"
"\tKey Generation Command:\n\t\t- Generate a key or provide a key to encrypt. If generating a key, use gen-<key_size_bytes>.\n\t\t  Command Examples: gen-28, gen-56, gen-128, eac91fd70ea04405bc4fc26dc4f5eb53\n\n"
"\tInput Shellcode File:\n\t\t- A binary file containing the shellcode to encrypt\n\n"
"\tOutput Shellcode File:\n\t\t- A file to write the encrypted shellcode to.\n\n\n"
"Optional Arguments:\n"
"\t-p :: Print the plaintext version of the shellcode & encryption key to stdout\n"
"\t-q :: Suppress all shellcode output in stdout\n"
"\t-t :: Test the shellcode via thread execution\n\n";

const char XorFunction[] =
"VOID Xor(PBYTE pData, SIZE_T SizeOfData, PBYTE pKey, SIZE_T SizeOfKey) {\n"
"	for (int i = 0, j = 0; i < SizeOfData; i++, j++) {\n"
"		if (j >= SizeOfKey) {\n"
"			j = 0;\n"
"		}\n"
"		pData[i] = pData[i] ^ pKey[j];\n"
"	}\n"
"}\n";

const char KeyDecryptionFunction[] =
"PBYTE DecryptKey(BYTE HintByte, PBYTE EncryptedKey, SIZE_T KeySize) {\n"
"    BYTE  KeyByte      = 0;\n"
"    PBYTE OriginalKey  = malloc(KeySize);\n"
"    if(!OriginalKey) {return NULL;}\n"
"    while (TRUE) { if (((EncryptedKey[0] ^ KeyByte) - 0) == HintByte) {break;} else {KeyByte++;}}\n"
"    for (int i = 0; i < KeySize; i++) {\n"
"       OriginalKey[i] = (BYTE)((EncryptedKey[i] ^ KeyByte) - i);\n"
"    }\n"
"    return OriginalKey; \n"
"}\n";