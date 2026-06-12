#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdint>

typedef uint64_t XUID;
#define INVALID_XUID                    ((XUID)0)

HRESULT XLiveProtectData(unsigned char *plain, unsigned long plain_size, unsigned char *cypher, unsigned long *p_cypher_size, DWORD dwTitleID, XUID _XamUserGetXUID_12, XUID _XamUserGetSigninInfo_12, bool randomize = true);
HRESULT XLiveUnprotectData(unsigned char *cypher, unsigned long cypher_size, unsigned char *plain, unsigned long *p_plain_size, DWORD dwTitleID, XUID *_XamUserGetXUID_12, XUID *_XamUserGetSigninInfo_12, DWORD *pdwTitleID, bool *p_title_id_ok);
