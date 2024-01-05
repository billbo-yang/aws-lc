// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "macho_parser.h"

int read_macho_file(const char *filename, MachOFile *macho) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return 0;
    }

    fread(&macho->machHeader, sizeof(MachOHeader), 1, file);

    macho->loadCommands = (LoadCommand *)malloc(macho->machHeader.sizeofcmds);
    fread(macho->loadCommands, macho->machHeader.sizeofcmds, 1, file);

    // Iterate through load commands to help determine how much memory to allocate for section information
    macho->numSections = 0;
    for (uint32_t i = 0; i < macho->machHeader.sizeofcmds / BIT_MODIFIER; i += macho->loadCommands[i].cmdsize / BIT_MODIFIER) {
        if (macho->loadCommands[i].cmd == LC_SEG) {
            SegmentLoadCommand *segment = (SegmentLoadCommand *)&macho->loadCommands[i];
            macho->numSections += segment->nsects;
        }
        else if (macho->loadCommands[i].cmd == LC_SYMTAB) {
            macho->numSections += 2;
        }
    }

    // Allocate memory for section information
    macho->sections = (SectionInfo *)malloc(macho->numSections * sizeof(SectionInfo));

    // Iterate through load commands again to populate section information
    uint32_t sectionIndex = 0;
    for (uint32_t i = 0; i < macho->machHeader.sizeofcmds / BIT_MODIFIER; i += macho->loadCommands[i].cmdsize / BIT_MODIFIER) {
        if (macho->loadCommands[i].cmd == LC_SEG) {
            SegmentLoadCommand *segment = (SegmentLoadCommand *)&macho->loadCommands[i];
            SectionHeader *sections = (SectionHeader *)&segment[1];
            for (uint32_t j = 0; j < segment->nsects; j++) {
                macho->sections[sectionIndex].offset = sections[j].offset;
                macho->sections[sectionIndex].size = sections[j].size;
                macho->sections[sectionIndex].name = strdup(sections[j].sectname);
                sectionIndex++;
            }
        } else if (macho->loadCommands[i].cmd == LC_SYMTAB) {
            SymtabLoadCommand *symtab = (SymtabLoadCommand *)&macho->loadCommands[i];
            macho->sections[sectionIndex].offset = symtab->symoff;
            macho->sections[sectionIndex].size = symtab->nsyms * sizeof(nList);
            macho->sections[sectionIndex].name = strdup("__symbol_table");
            sectionIndex++;
            macho->sections[sectionIndex].offset = symtab->stroff;
            macho->sections[sectionIndex].size = symtab->strsize;
            macho->sections[sectionIndex].name = strdup("__string_table");
            sectionIndex++;
        }
    }

    fclose(file);
    return 1;
}

void free_macho_file(MachOFile *macho) {
    free(macho->loadCommands);
    for (uint32_t i = 0; i < macho->numSections; i++) {
        free(macho->sections[i].name);
    }
    free(macho->sections);
}

void print_macho_section_info(MachOFile *macho) {
    printf("Number of sections: %u\n", macho->numSections);
    for (uint32_t i = 0; i < macho->numSections; i++) {
        printf("Section: %s, Offset: %u, Size: %zu\n", macho->sections[i].name,
               macho->sections[i].offset, macho->sections[i].size);
    }
}

uint8_t* get_macho_section_data(char *filename, MachOFile *macho, const char *sectionName, size_t *size, uint32_t *offset) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return NULL;
    }
    for (uint32_t i = 0; i < macho->numSections; i++) {
        if (strcmp(macho->sections[i].name, sectionName) == 0) {
            uint8_t *sectionData = (uint8_t *)malloc(macho->sections[i].size);
            if (!sectionData) {
                fclose(file);
                perror("Memory allocation error");
                return NULL;
            }

            fseek(file, macho->sections[i].offset, SEEK_SET);
            fread(sectionData, 1, macho->sections[i].size, file);

            if (size != NULL) {
                *size = macho->sections[i].size;
            }
            if (offset) {
                *offset = macho->sections[i].offset;
            }

            fclose(file);
            return sectionData;
        }
    }

    fclose(file);
    return NULL;
}

uint32_t find_macho_symbol_index(uint8_t *symbolTableData, size_t symbolTableSize, uint8_t *stringTableData, size_t stringTableSize, const char *symbolName, uint32_t *base) {
    if (symbolTableData == NULL || stringTableData == NULL) {
        perror("Inputs cannot be null");
        return 0;
    }

    char* stringTable = (char *)malloc(stringTableSize);
    memcpy(stringTable, stringTableData, stringTableSize);

    int found = 0;
    uint32_t index = 0;
    for (uint32_t i = 0; i < symbolTableSize / sizeof(nList); i++) {
        nList *symbol = (nList *)(symbolTableData + i * sizeof(nList));
        if (strcmp(symbolName, &stringTable[symbol->n_un.n_strx]) == 0) {
            if (!found) {
                index = symbol->n_value;
                found = 1;
            } else {
                perror("Duplicate symbol %s found\n");
                return 0;
            }
            
        }
    }

    free(stringTable);
    if (base) {
        index = index - *base;
    }
    return index;
}
