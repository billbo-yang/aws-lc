// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#ifndef INJECT_HASH_H
#define INJECT_HASH_H

uint8_t* read_object(const char *filename, size_t *size);
int write_object(const char *filename, uint8_t *object, size_t size);
uint32_t find_hash(uint8_t *objectBytes, size_t objectBytesSize, uint8_t* hash, size_t hashSize);
int do_apple(char *objectFile, uint8_t **textModule, size_t *textModuleSize, uint8_t **rodataModule, size_t *rodataModuleSize);
uint8_t* size_to_little_endian_bytes(size_t size);

#endif
