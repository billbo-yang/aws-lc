// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <assert.h>

#include "../common.h"
#include "macho_tests.h"

#define TEST_FILE "test_macho"

machofile *MachoTestFixture::expected_macho;
symbol_info *MachoTestFixture::expected_symtab;
uint32_t MachoTestFixture::num_syms;
char MachoTestFixture::expected_strtab[EXPECTED_STRTAB_SIZE];
int MachoTestFixture::text_data[TEXT_DATA_SIZE];
char MachoTestFixture::const_data[CONST_DATA_SIZE];
uint32_t MachoTestFixture::expected_symbol1_ind;
uint32_t MachoTestFixture::expected_symbol2_ind;

TEST_F(MachoTestFixture, TestReadMachoFile) {
    machofile test_macho_file;
    if (!read_macho_file(TEST_FILE, &test_macho_file)) {
        LOG_ERROR("Failed to read macho_file");
    }

    EXPECT_TRUE(memcmp(&test_macho_file.macho_header, &expected_macho->macho_header, sizeof(macho_header)) == 0);
    EXPECT_EQ(test_macho_file.num_sections, expected_macho->num_sections);
    EXPECT_TRUE(memcmp(test_macho_file.sections, expected_macho->sections, test_macho_file.num_sections * sizeof(section_info)) == 0);
}

TEST_F(MachoTestFixture, TestGetMachoSectionData) {
    uint8_t *text_section = NULL;
    size_t text_section_size;

    uint8_t *const_section = NULL;
    size_t const_section_size;

    uint8_t *symbol_table = NULL;
    size_t symbol_table_size;

    uint8_t *string_table = NULL;
    size_t string_table_size;

    text_section = get_macho_section_data(TEST_FILE, expected_macho, "__text", &text_section_size, NULL);
    const_section = get_macho_section_data(TEST_FILE, expected_macho, "__const", &const_section_size, NULL);
    symbol_table = get_macho_section_data(TEST_FILE, expected_macho, "__symbol_table", &symbol_table_size, NULL);
    string_table = get_macho_section_data(TEST_FILE, expected_macho, "__string_table", &string_table_size, NULL);

    ASSERT_TRUE(memcmp(text_section, text_data, text_section_size) == 0);
    ASSERT_TRUE(memcmp(const_section, const_data, const_section_size) == 0);
    ASSERT_TRUE(memcmp(symbol_table, expected_symtab, symbol_table_size) == 0);
    ASSERT_TRUE(memcmp(string_table, expected_strtab, string_table_size) == 0);
}

TEST_F(MachoTestFixture, TestFindMachoSymbolIndex) {
    uint8_t *symbol_table = NULL;
    size_t symbol_table_size;

    uint8_t *string_table = NULL;
    size_t string_table_size;

    symbol_table = get_macho_section_data(TEST_FILE, expected_macho, "__symbol_table", &symbol_table_size, NULL);
    string_table = get_macho_section_data(TEST_FILE, expected_macho, "__string_table", &string_table_size, NULL);

    uint32_t symbol1_index = find_macho_symbol_index(symbol_table, symbol_table_size, string_table, string_table_size, "symbol1", NULL);

    ASSERT_EQ(symbol1_index, expected_symbol1_ind);
}
