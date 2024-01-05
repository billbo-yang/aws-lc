// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <unistd.h>

#include "common.h"
// #include "inject_hash.h"
#include "macho_parser.h"

#include <openssl/base.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>

static uint8_t* read_object(const char *filename, size_t *size) {
    FILE *file = fopen(filename, "rb");

    uint8_t *objectBytes = NULL;

    if (file == NULL) {
        LOG_ERROR("Error opening file");
        goto end;
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    objectBytes = malloc(file_size);

    if (objectBytes == NULL) {
        LOG_ERROR("Error allocating memory");
        goto end;
    }

    *size = fread(objectBytes, 1, file_size, file);

    if (*size != file_size) {
        LOG_ERROR("Error reading file");
        free(objectBytes);
        objectBytes = NULL;
        goto end;
    }

end:
    fclose(file);
    return objectBytes;
}

static int write_object(const char *filename, uint8_t *bytes, size_t size) {
    int ret = 0;

    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        LOG_ERROR("Error opening file to write");
        goto end;
    }

    size_t written = fwrite(bytes, sizeof(uint8_t), size, file);
    if (written != size) {
        LOG_ERROR("Error writing file");
        goto end;
    }

    ret = 1;

end:
    fclose(file);
    return ret;
}

static uint32_t find_hash(uint8_t *objectBytes, size_t objectBytesSize, uint8_t* hash, size_t hashSize) {
    uint8_t *ptr = memmem(objectBytes, objectBytesSize, hash, hashSize);
    if (ptr == NULL) {
        LOG_ERROR("Error finding hash in object");
        return 0;
    }

    return ptr-objectBytes;
}

static int do_apple(char *objectFile, uint8_t **textModule, size_t *textModuleSize, uint8_t **rodataModule, size_t *rodataModuleSize) {
    uint8_t *textSection = NULL;
    size_t textSectionSize;
    uint32_t textSectionOffset;

    uint8_t *rodataSection = NULL;
    size_t rodataSectionSize;
    uint32_t rodataSectionOffset;

    uint8_t *symbolTable = NULL;
    size_t symbolTableSize;

    uint8_t *stringTable = NULL;
    size_t stringTableSize;

    uint32_t textStart;
    uint32_t textEnd;
    uint32_t rodataStart;
    uint32_t rodataEnd;

    MachOFile macho;

    int ret = 0;

    if (read_macho_file(objectFile, &macho)) {
        textSection = get_macho_section_data(objectFile, &macho, "__text", &textSectionSize, &textSectionOffset);
        if (textSection == NULL) {
            LOG_ERROR("Error getting text section");
            goto end;
        }
        rodataSection = get_macho_section_data(objectFile, &macho, "__const", &rodataSectionSize, &rodataSectionOffset);
        // We aren't guaranteed to have a rodata section so we don't want to error out in that case
        symbolTable = get_macho_section_data(objectFile, &macho, "__symbol_table", &symbolTableSize, NULL);
        if(symbolTable == NULL) {
            LOG_ERROR("Error getting symbol table");
            goto end;
        }
        stringTable = get_macho_section_data(objectFile, &macho, "__string_table", &stringTableSize, NULL);
        if(stringTable == NULL) {
            LOG_ERROR("Error getting string table");
            goto end;
        }
        free_macho_file(&macho);

        textStart = find_macho_symbol_index(symbolTable, symbolTableSize, stringTable, stringTableSize, "_BORINGSSL_bcm_text_start", &textSectionOffset);
        textEnd = find_macho_symbol_index(symbolTable, symbolTableSize, stringTable, stringTableSize, "_BORINGSSL_bcm_text_end", &textSectionOffset);
        rodataStart = find_macho_symbol_index(symbolTable, symbolTableSize, stringTable, stringTableSize, "_BORINGSSL_bcm_rodata_start", &rodataSectionOffset);
        rodataEnd = find_macho_symbol_index(symbolTable, symbolTableSize, stringTable, stringTableSize, "_BORINGSSL_bcm_rodata_end", &rodataSectionOffset);

        if (!textStart || !textEnd) {
            LOG_ERROR("Could not find .text module boundaries in object");
            goto end;
        }

        if ((!rodataStart) != (!rodataSection)) {
            LOG_ERROR(".rodata start marker inconsistent with rodata section presence");
            goto end;
        }

        if ((!rodataStart) != (!rodataEnd)) {
            LOG_ERROR(".rodata marker presence inconsistent");
            goto end;
        }

        if (textStart > textSectionSize || textStart > textEnd || textEnd > textSectionSize) {
            LOG_ERROR("Invalid .text module boundaries: start: %x, end: %x, max: %zx", textStart, textEnd, textSectionSize);
            goto end;
        }

        if (rodataSection != NULL && (rodataStart > rodataSectionSize || rodataStart > rodataEnd || rodataEnd > rodataSectionSize)) {
            LOG_ERROR("Invalid .rodata module boundaries: start: %x, end: %x, max: %zx", rodataStart, rodataEnd, rodataSectionSize);
            goto end;
        }

        // Get text and rodata modules from textSection/rodataSection using the obtained indices
        *textModuleSize = textEnd - textStart;
        *textModule = malloc(*textModuleSize);
        memcpy(*textModule, textSection + textStart, *textModuleSize);

        if (rodataSection != NULL) {
            *rodataModuleSize = rodataEnd - rodataStart;
            *rodataModule = malloc(*rodataModuleSize);
            memcpy(*rodataModule, rodataSection + rodataStart, *rodataModuleSize);
        }
        ret = 1;
    } else {
        LOG_ERROR("Error reading Mach-O file");
        goto end;
    }

end:
    // If any of these sections are NULL, they were never allocated in the first place
    if (textSection != NULL) {
        free(textSection);
    }
    if (rodataSection != NULL) {
        free(rodataSection);
    }
    if (symbolTable != NULL) {
        free(symbolTable);
    }
    if (stringTable != NULL) {
        free(stringTable);
    }

    return ret;
}

static void size_to_little_endian_bytes(size_t size, uint8_t *result) {
    for (int i = 0; i < 8; ++i) {
        result[i] = (size >> (i * 8)) & 0xFF;
    }
}

int main(int argc, char *argv[]) {
    char *arInput = NULL;
    char *oInput = NULL;
    char *outPath = NULL;
    int appleFlag = 0;

    int ret = EXIT_FAILURE;

    uint8_t uninitHash[] = {
        0xae, 0x2c, 0xea, 0x2a, 0xbd, 0xa6, 0xf3, 0xec, 
        0x97, 0x7f, 0x9b, 0xf6, 0x94, 0x9a, 0xfc, 0x83, 
        0x68, 0x27, 0xcb, 0xa0, 0xa0, 0x9f, 0x6b, 0x6f, 
        0xde, 0x52, 0xcd, 0xe2, 0xcd, 0xff, 0x31, 0x80,
    };

    uint8_t *objectBytes = NULL;
    size_t objectBytesSize;
    
    uint8_t *textModule = NULL;
    size_t textModuleSize;
    uint8_t *rodataModule = NULL;
    size_t rodataModuleSize;

    uint8_t *calculatedHash = NULL;
    uint8_t lengthBytes[8];

    uint32_t hashIndex;

    int opt;
    while ((opt = getopt(argc, argv, "a:o:p:f")) != -1) {
        switch(opt) {
            case 'a':
                arInput = optarg;
                break;
            case 'o':
                oInput = optarg;
                break;
            case 'p':
                outPath = optarg;
                break;
            case 'f':
                appleFlag = 1;
                break;
            case '?':
            default:
                LOG_ERROR("Usage: %s [-a in-archive] [-o in-object] [-p out-path] [-f apple-flag]", argv[0]);
                goto end;
        }
    }

    if ((arInput == NULL && oInput == NULL) || outPath == NULL) {
        LOG_ERROR("Usage: %s [-a in-archive] [-o in-object] [-p out-path] [-f apple-flag]", argv[0]);
        LOG_ERROR("Note that either the -a or -o option and -p options are required.");
        goto end;
    }

    if (arInput) {
        // Do something with archive input
    } else {
        objectBytes = read_object(oInput, &objectBytesSize);
        if (objectBytes == NULL) {
            LOG_ERROR("Error reading file");
            goto end;
        }
    }

    if (appleFlag == 1) {
        if (!do_apple(oInput, &textModule, &textModuleSize, &rodataModule, &rodataModuleSize)) {
            LOG_ERROR("Error getting text and rodata modules from Apple OS object");
            goto end;
        }
    } else {
        // Handle Linux
    }

    if(textModule == NULL || rodataModule == NULL) {
        LOG_ERROR("Error getting text or rodata section");
        goto end;
    }

    hashIndex = find_hash(objectBytes, objectBytesSize, uninitHash, sizeof(uninitHash));
    if (!hashIndex) {
        LOG_ERROR("Error finding hash");
        goto end;
    }

    uint8_t zeroKey[64] = {0};
    HMAC_CTX ctx;
    if (!HMAC_Init(&ctx, &zeroKey, sizeof(zeroKey), EVP_sha256())) {
        LOG_ERROR("Error in HMAC_Init()");
        goto end;
    }

    if(rodataModule != NULL) {
        size_to_little_endian_bytes(textModuleSize, lengthBytes);
        if (!HMAC_Update(&ctx, lengthBytes, 8)) {
            LOG_ERROR("Error in HMAC_Update() of textModuleSize");
            goto end;
        }
        if (!HMAC_Update(&ctx, textModule, textModuleSize)) {
            LOG_ERROR("Error in HMAC_Update() of textModule");
            goto end;
        }
        size_to_little_endian_bytes(rodataModuleSize, lengthBytes);
        if (!HMAC_Update(&ctx, lengthBytes, 8)) {
            LOG_ERROR("Error in HMAC_Update() of rodataModuleSize");
            goto end;
        }
        if (!HMAC_Update(&ctx, rodataModule, rodataModuleSize)) {
            LOG_ERROR("Error in HMAC_Update() of rodataModule");
            goto end;
        }
    } else {
        if (!HMAC_Update(&ctx, textModule, textModuleSize)) {
            LOG_ERROR("Error in HMAC_Update() of textModule");
            goto end;
        }
    }

    calculatedHash = malloc(HMAC_size(&ctx));
    unsigned int calculatedHashLen;
    if (!HMAC_Final(&ctx, calculatedHash, &calculatedHashLen)) {
        LOG_ERROR("Error in HMAC_Final()");
        goto end;
    }

    memcpy(objectBytes + hashIndex, calculatedHash, calculatedHashLen);
    if (!write_object(outPath, objectBytes, objectBytesSize)) {
        LOG_ERROR("Error writing file");
        goto end;
    }

    ret = EXIT_SUCCESS;

end:
    free(textModule);
    free(rodataModule);
    free(objectBytes);
    free(calculatedHash);
    exit(ret);
}
