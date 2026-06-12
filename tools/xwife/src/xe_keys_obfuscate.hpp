#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>

NTSTATUS XeKeysObfuscate(int one, unsigned char *plain, unsigned long plain_size, unsigned char *cypher, unsigned long *p_cypher_size);
BOOL XeKeysUnObfuscate(int one, unsigned char *cypher, unsigned long cypher_size, unsigned char *plain, unsigned long *p_plain_size);
