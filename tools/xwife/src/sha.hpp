#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

HRESULT XLivepComputeSHA256Digest(unsigned char const *data, unsigned long data_size, unsigned char *digest);
