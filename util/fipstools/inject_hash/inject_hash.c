// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "inject_hash.h"
#include "macho_parser.h"

#include <openssl/base.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>

uint8_t* read_object(const char *filename, size_t *size) {
    FILE *file = fopen(filename, "rb");

    uint8_t *objectBytes = NULL;

    if (file == NULL) {
        perror("Error opening file");
        goto end;
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    objectBytes = (uint8_t *)malloc(file_size);

    if (objectBytes == NULL) {
        perror("Error allocating memory");
        goto end;
    }

    *size = fread(objectBytes, 1, file_size, file);

    if (*size != file_size) {
        perror("Error reading file");
        free(objectBytes);
        objectBytes = NULL;
        goto end;
    }

end:
    fclose(file);
    return objectBytes;
}

int write_object(const char *filename, uint8_t *bytes, size_t size) {
    int ret = 0;

    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Error opening file to write");
        goto end;
    }

    size_t written = fwrite(bytes, sizeof(uint8_t), size, file);
    if (written != size) {
        perror("Error writing file");
        goto end;
    }

    ret = 1;

end:
    fclose(file);
    return ret;
}

uint32_t find_hash(uint8_t *objectBytes, size_t objectBytesSize, uint8_t* hash, size_t hashSize) {
    uint8_t *ptr = memmem(objectBytes, objectBytesSize, hash, hashSize);
    if (ptr == NULL) {
        perror("Error finding hash in object");
        return 0;
    }

    return ptr-objectBytes;
}

int do_apple(char *objectFile, uint8_t **textModule, size_t *textModuleSize, uint8_t **rodataModule, size_t *rodataModuleSize) {
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
            perror("Error getting text section");
            goto end;
        }
        rodataSection = get_macho_section_data(objectFile, &macho, "__const", &rodataSectionSize, &rodataSectionOffset);
        if (rodataSection == NULL) {
            perror("Error getting rodata section");
            goto end;
        }
        symbolTable = get_macho_section_data(objectFile, &macho, "__symbol_table", &symbolTableSize, NULL);
        if(symbolTable == NULL) {
            perror("Error getting symbol table");
            goto end;
        }
        stringTable = get_macho_section_data(objectFile, &macho, "__string_table", &stringTableSize, NULL);
        if(stringTable == NULL) {
            perror("Error getting string table");
            goto end;
        }
        free_macho_file(&macho);

        textStart = find_macho_symbol_index(symbolTable, symbolTableSize, stringTable, stringTableSize, "_BORINGSSL_bcm_text_start", &textSectionOffset);
        textEnd = find_macho_symbol_index(symbolTable, symbolTableSize, stringTable, stringTableSize, "_BORINGSSL_bcm_text_end", &textSectionOffset);
        rodataStart = find_macho_symbol_index(symbolTable, symbolTableSize, stringTable, stringTableSize, "_BORINGSSL_bcm_rodata_start", &rodataSectionOffset);
        rodataEnd = find_macho_symbol_index(symbolTable, symbolTableSize, stringTable, stringTableSize, "_BORINGSSL_bcm_rodata_end", &rodataSectionOffset);

        if (!textStart || !textEnd) {
            perror("Could not find .text module boundaries in object\n");
            goto end;
        }

        if ((!rodataStart) != (!rodataSection)) {
            perror(".rodata start marker inconsistent with rodata section presence\n");
            goto end;
        }

        if ((!rodataStart) != (!rodataEnd)) {
            perror(".rodata marker presence inconsistent\n");
            goto end;
        }

        if (textStart > textSectionSize || textStart > textEnd || textEnd > textSectionSize) {
            fprintf(stderr, "invalid module __text boundaries: start: %x, end: %x, max: %zx", textStart, textEnd, textSectionSize);
            goto end;
        }

        if (rodataSection != NULL && (rodataStart > rodataSectionSize || rodataStart > rodataEnd || rodataEnd > rodataSectionSize)) {
            fprintf(stderr, "invalid module __rodata boundaries: start: %x, end: %x, max: %zx", rodataStart, rodataEnd, rodataSectionSize);
            goto end;
        }

        // Get text and rodata modules from textSection/rodataSection using the obtained indices
        *textModuleSize = textEnd - textStart;
        *textModule = (uint8_t *)malloc(*textModuleSize);
        memcpy(*textModule, textSection + textStart, *textModuleSize);

        if (rodataSection != NULL) {
            *rodataModuleSize = rodataEnd - rodataStart;
            *rodataModule = (uint8_t *)malloc(*rodataModuleSize);
            memcpy(*rodataModule, rodataSection + rodataStart, *rodataModuleSize);
        }
        ret = 1;
    } else {
        perror("Error reading Mach-O file");
        goto end;
    }

end:
    if (textSection != NULL) {
        free(textSection);
        textSection = NULL;
    }
    if (rodataSection != NULL) {
        free(rodataSection);
        rodataSection = NULL;
    }
    if (symbolTable != NULL) {
        free(symbolTable);
        symbolTable = NULL;
    }
    if (stringTable != NULL) {
        free(stringTable);
        stringTable = NULL;
    }

    return ret;
}

uint8_t* size_to_little_endian_bytes(size_t size) {
    uint8_t* bytes = (uint8_t*)malloc(8);
    for (int i = 0; i < 8; ++i) {
        bytes[i] = (size >> (i * 8)) & 0xFF;
    }

    return bytes;
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
    uint8_t *lengthBytes = NULL;

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
                fprintf(stderr, "Usage: %s [-a in-archive] [-o in-object] [-p out-path] [-f apple-flag]\n", argv[0]);
                goto end;
        }
    }

    if ((arInput == NULL && oInput == NULL) || outPath == NULL) {
        fprintf(stderr, "Usage: %s [-a in-archive] [-o in-object] [-p out-path] [-f apple-flag]\n", argv[0]);
        fprintf(stderr, "Note that either the -a or -o option and -p options are required.\n");
        goto end;
    }

    if (arInput) {
        // Do something with archive input
    } else {
        objectBytes = read_object(oInput, &objectBytesSize);
        if (objectBytes == NULL) {
            perror("Error reading file");
            goto end;
        }
    }

    if (appleFlag == 1) {
        if (!do_apple(oInput, &textModule, &textModuleSize, &rodataModule, &rodataModuleSize)) {
            perror("Error getting text and rodata modules from Apple OS object");
            goto end;
        }
    } else {
        // Handle Linux
    }

    if(textModule == NULL || rodataModule == NULL) {
        perror("Error getting text or rodata section");
        goto end;
    }

    hashIndex = find_hash(objectBytes, objectBytesSize, uninitHash, sizeof(uninitHash));
    if (!hashIndex) {
        perror("Error finding hash");
        goto end;
    }

    uint8_t zeroKey[64] = {0};
    HMAC_CTX ctx;
    if (!HMAC_Init(&ctx, &zeroKey, sizeof(zeroKey), EVP_sha256())) {
        perror("Error in HMAC_Init()");
        goto end;
    }

    if(rodataModule != NULL) {
        lengthBytes = size_to_little_endian_bytes(textModuleSize);
        if (!HMAC_Update(&ctx, lengthBytes, 8)) {
            perror("Error in HMAC_Update() of textModuleSize");
            goto end;
        }
        free(lengthBytes);
        lengthBytes = NULL;
        if (!HMAC_Update(&ctx, textModule, textModuleSize)) {
            perror("Error in HMAC_Update() of textModule");
            goto end;
        }
        lengthBytes = size_to_little_endian_bytes(rodataModuleSize);
        if (!HMAC_Update(&ctx, lengthBytes, 8)) {
            perror("Error in HMAC_Update() of rodataModuleSize");
            goto end;
        }
        free(lengthBytes);
        lengthBytes = NULL;
        if (!HMAC_Update(&ctx, rodataModule, rodataModuleSize)) {
            perror("Error in HMAC_Update() of rodataModule");
            goto end;
        }
    } else {
        if (!HMAC_Update(&ctx, textModule, textModuleSize)) {
            perror("Error in HMAC_Update() of textModule");
            goto end;
        }
    }

    calculatedHash = (uint8_t *)malloc(HMAC_size(&ctx));
    unsigned int calculatedHashLen;
    if (!HMAC_Final(&ctx, calculatedHash, &calculatedHashLen)) {
        perror("Error in HMAC_Final()");
        goto end;
    }

    memcpy(objectBytes + hashIndex, calculatedHash, calculatedHashLen);
    if (!write_object(outPath, objectBytes, objectBytesSize)) {
        perror("Error writing file");
        goto end;
    }

    ret = EXIT_SUCCESS;

end:
    if (textModule != NULL) {
        free(textModule);
        textModule = NULL;
    }
    if (rodataModule != NULL) {
        free(rodataModule);
        rodataModule = NULL;
    }
    if (objectBytes != NULL) {
        free(objectBytes);
        objectBytes = NULL;
    }
    if (calculatedHash != NULL) {
        free(calculatedHash);
        calculatedHash = NULL;
    }
    if (lengthBytes != NULL) {
        free(lengthBytes);
        lengthBytes = NULL;
    }
    exit(ret);
}
