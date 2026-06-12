# XLive Research

Research pertaining to Games for Windows Live (GFWL) xlive.dll.

## Tools

### xwife

This tool is a standalone C++ program that implements the major cryptographic functionality of xlive.dll. It does not require xlive.dll. Features include:

* PanoramaCryptoCBC
  - g_pcbcObfuscation
  - ~~g_pcbcXLiveDRM~~
  - g_pcbcSystemLink
  - g_pcbcXLiveUserData
* XeKeysObfuscate
* XeKeysUnObfuscate
* XLiveProtectData
* XLiveUnprotectData

If you just want the AES keys, then the `aes.cpp` file is what you're looking for.

## Patterns

The [ImHex](https://imhex.werwolv.net/) patterns are for the on disk format of XeKeysObfuscate/XeKeysUnObfuscate and XLiveProtectData/XLiveUnprotectData data. "Debug" refers to the development dlls which have all the crypto stripped and "Release" refers to the normal dlls.

## Configs

The ScyllaHide config should keep the anti-debug off your back. The patch file for xlive 3.5.95.0 neutralizes the `PEVerifyHash` check (`?PEVerifyHash@CPEMgr@@AAEJPAVCHashMgr@@IPAVC_LOADED_MODULE_LIST@@@Z`, the famous `8B FF 55 8B EC 83 EC 20 53 56 57 8D 45 E0 33 F6 50 FF 75 0C 8B F9` signature) which should let you put breakpoints in more places without getting killed. There are countless other checks for IAT, single step exceptions, etc..., but this gets you 99% of the way there. And a lot of that other stuff gets patched at runtime by WARBIRD so it's harder to nop out like this. You'll also want exceptions set to Break On: Second Chance, Logging: Log exception, Exception handled by: Debuggee, since xlive uses SEH to catch divisions by zero and access violations it causes on purpose.

## Scripts

The scripts are mostly scraps from when I was testing stuff while writing xwife. They shouldn't be too useful on their own but I've included them anyway in case someone finds them useful. The dll emulation scripts are for the peacestoned xlive 1.2.241.0 (more info in the next section, use my fork). The frida agents are for xlive 3.5.95.0 and assume ScyllaHide is already doing its job (more info in the previous section).

## Notes

### Warbird

Microsoft WARBIRD is a code obfuscator used on xlive. The older versions aren't the worst thing in the world and several tools exist to deobfuscate the protected code: [peacestone](https://github.com/UMSKT/peacestone) and [warturd](https://gitlab.com/GlitchyScripts/xlln-modules/-/tree/master/xlln-modules/xlln-warturd?ref_type=heads). I haven't looked at the newer versions at all, but I can't imagine it's too much of a step up. I chose to [modify peacestone](https://github.com/widberg/peacestone) (with help from WitherOrNot and cross referencing warturd) to work better on xlive 1.2.241.0. Since Microsoft can't change the crypto or file formats without breaking everyone's stuff we're lucky that we can reverse engineer the old dlls and it will "just work" with the new dlls. No need to deal with newer WARBIRD versions!

### Syncrosoft MCFACT

For some reason Microsoft decided that they wanted to protect XLiveProtectData and XLiveUnprotectData with Syncrosoft MCFACT. Nothing else in the dll uses this from what I can tell. It's really annoying. A few comments across hacker news and reddit have mentioned it ([1](https://news.ycombinator.com/item?id=1157262), [2](https://www.reddit.com/r/gaming/comments/bu69y/comment/c0okhji/), [3](https://www.reddit.com/r/IAmA/s/uZbZ1iwSyg)) but I couldn't find much beyond that, I guess it wasn't that popular. I'd never heard of it before.

This [Syncrosoft MCFACT PowerPoint](http://re-trust.dit.unitn.it/files/20080311Doc/harder-Syncrosoft-MCFACT.pdf) from the Re-trust Sixth Quarterly Meeting (March 11, 2008) is the holy grail. It details how it works and shows code snippets. Unfortunately MCFACT is pretty good and I believe them when they say it can't be decomposed. So I just yanked the lookup tables and driver code out of the dll wholesale.

### AES Whitebox

The AES block cypher code is a "whitebox" implementation, if you even want to call it that. They just bake the primitives and round keys into lookup tables instead of doing it procedurally. g_pcbcObfuscation and g_pcbcXLiveUserData don't even use the standard number of rounds or have a master key that the round keys can be derived from with a key schedule algorithm. g_pcbcSystemLink uses the standard number of rounds and has a recoverable master key from the real AES-128 key schedule, but it was already known from the Xbox 360.

This whitebox isn't MCFACT, it's their own thing. I don't know why they decided to do their own thing when MCFACT advertises a comprehensive cryptography toolbox that includes AES, but maybe that wasn't available at the time, I'm not certain on the timeline.

## Other Stuff

* [cxkes.me - XUID Lookup](https://cxkes.me/xbox/xuid) - Online XUID Lookup tool
* [GfWLUtility](https://github.com/InvoxiPlayGames/GfWLUtility) - Utility for working with Games for Windows - LIVE
* [spaday](https://github.com/widberg/spaday) - GFWL/Xbox 360 [SPAFILE](https://free60.org/System-Software/Formats/SPA/) parser
