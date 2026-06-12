#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "c_small_buffer.hpp"

HRESULT ObfuscationEncryptBlock(SB_PTR<unsigned char> plain, SB_PTR<unsigned char> cypher, unsigned long sixteen);
HRESULT ObfuscationDecryptBlock(SB_PTR<unsigned char> cypher, SB_PTR<unsigned char> plain, unsigned long sixteen);
HRESULT SystemLinkEncryptBlock(SB_PTR<unsigned char> plain, SB_PTR<unsigned char> cypher, unsigned long sixteen);
HRESULT SystemLinkDecryptBlock(SB_PTR<unsigned char> cypher, SB_PTR<unsigned char> plain, unsigned long sixteen);
HRESULT UserDataEncryptBlock(SB_PTR<unsigned char> plain, SB_PTR<unsigned char> cypher, unsigned long sixteen);
HRESULT UserDataDecryptBlock(SB_PTR<unsigned char> cypher, SB_PTR<unsigned char> plain, unsigned long sixteen);
