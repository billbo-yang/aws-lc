#ifndef MACHO_PARSER_H
#define MACHO_PARSER_H

#include <mach-o/loader.h>
#include <mach-o/nlist.h>

typedef struct {
    uint32_t offset;
    size_t size;
    char *name;
} SectionInfo;

// Since we only support 64-bit architectures, we don't need to account for any of the 32-bit structures
#define LC_SEG LC_SEGMENT_64
#define BIT_MODIFIER 8

typedef struct mach_header_64 MachOHeader;
typedef struct load_command LoadCommand;
typedef struct segment_command_64 SegmentLoadCommand;
typedef struct symtab_command SymtabLoadCommand;
typedef struct section_64 SectionHeader;
typedef struct nlist_64 nList;

typedef struct {
    MachOHeader machHeader;
    LoadCommand *loadCommands;
    SectionInfo *sections;
    uint32_t numSections;
} MachOFile;

int readMachOFile(const char *filename, MachOFile *macho);
void freeMachOFile(MachOFile *macho);
void printSectionInfo(MachOFile *macho);
SectionInfo* getSectioninfo(MachOFile *macho, const char *sectionName);
uint8_t* getSectionData(char* filename, MachOFile *macho, const char *sectionName, size_t *size, uint32_t *offset);
uint32_t findSymbolIndex(uint8_t *sectionData, size_t sectionSize, uint8_t *stringTableData, size_t stringTableSize, const char *symbolName, uint32_t *base);

#endif
