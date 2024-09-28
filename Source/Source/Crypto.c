#pragma once
#include "../Include/Crypto.h"

/*
    Description: Encrypt a byte array with XOR

    Parameter: PBYTE pData:       A pointer to the bytes to encrypt
    Parameter: SIZE_T SizeOfData: The size of the byte array pointed to by pData
    Parameter: PBYTE pKey:        A pointer to the keys bytes
    Parameter: Size_T SizeOfKey:  The size of the byte array pointed to by pKey
*/
VOID Xor(PBYTE pData, SIZE_T SizeOfData, PBYTE pKey, SIZE_T SizeOfKey) {

    for (int i = 0, j = 0; i < SizeOfData; i++, j++) {

        if (j >= SizeOfKey) {
            j = 0;
        }

        pData[i] = pData[i] ^ pKey[j];

    }

}

/*
    Description: Creates a random encryption key for the shellcode and then encrypts it. Uses pointers
                 to return the encrypted key / original key.

    Parameter: BYTE HintByte: The first byte of the encryption key.
    Parameter: SIZE_T KeySize: The size of the key to generate
    Parameter: PBYTE* OutEncryptedKey: A pointer to a byte array that receives the encrypted key
    Parameter: PBYTE* OutOriginalKey: A pointer to a byte array that receives the plaintext key
*/
VOID CreateEncryptedKey(BYTE HintByte, SIZE_T KeySize, PBYTE* OutEncryptedKey, PBYTE* OutOriginalKey) {

    for (int i = 0; i < 100; i++) {
        srand((unsigned int)time(NULL));  // Seed
    }

    BYTE	KeyByte      = (rand() % 0xFF) + 0x01;
    PBYTE	OriginalKey  = (PBYTE)malloc(KeySize),
            EncryptedKey = (PBYTE)malloc(KeySize);

    for (int i = 0; i < 100; i++) {
        srand((unsigned int)time(NULL));  // Seed
    }

    // Set hint byte
    OriginalKey[0] = HintByte;

    // Generate the rest of the key
    for (int i = 1; i < KeySize; i++) {
        OriginalKey[i] = (BYTE)rand() % 0xFF;
    }
    //PrintKeyC(OriginalKey, KeySize);

    // Encrypt the key
    for (int i = 0; i < KeySize; i++) {
        EncryptedKey[i] = (BYTE)((OriginalKey[i] + i) ^ KeyByte);
    }

    // Write data to pointers
    *OutEncryptedKey = EncryptedKey;
    *OutOriginalKey = OriginalKey;

}

/*
    Description: Encrypts a key and writes the byte used for encryption to a pointer. Returns a pointer to 
                 the encryption key.

    Parameter: PBYTE pKey:        A pointer to a byte array that is the key to encrypt
    Parameter: SIZE_T KeySize:    The size of the key to encrypt
    Parameter: PBYTE* OutKeyByte: A pointer to write the encrypt key byte to. This is the key for the encryption key. 
*/
PBYTE EncryptKey(PBYTE pKey, SIZE_T KeySize, PBYTE* OutKeyByte) {

    for (int i = 0; i < 100; i++) {
        srand((unsigned int)time(NULL));  // Seed
    }

    BYTE	KeyByte      = (rand() % 0xFF) + 0x01,
            HintByte     = pKey[1];
    PBYTE	EncryptedKey = (PBYTE)malloc(KeySize);

    for (int i = 0; i < 100; i++) {
        srand((unsigned int)time(NULL));  // Seed
    }

    for (int i = 0; i < KeySize; i++) {
        EncryptedKey[i] = (BYTE)((pKey[i] + i) ^ KeyByte);
    }

    *OutKeyByte = &KeyByte;

    return EncryptedKey;
}