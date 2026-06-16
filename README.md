# XLive Research

Research pertaining to Games for Windows Live (GFWL) xlive.dll.

## Tools

### xwife

This tool is a standalone C++ program that implements the major cryptographic functionality of xlive.dll. It does not require xlive.dll.

Features include:

* PanoramaCryptoCBC
  - g_pcbcObfuscation
  - g_pcbcSystemLink
  - g_pcbcXLiveDRM
  - g_pcbcXLiveUserData
* XeKeysObfuscate
* XeKeysUnObfuscate
* XLiveProtectData
* XLiveUnprotectData

If you just want the AES keys, then the `aes.cpp` file is what you're looking for.

## Patterns

The [ImHex](https://imhex.werwolv.net/) patterns are for the on-disk format of `XeKeysObfuscate`/`XeKeysUnObfuscate` and `XLiveProtectData`/`XLiveUnprotectData` data. "Debug" refers to the development dlls which have all the crypto stripped and "Release" refers to the normal dlls.

## Configs

x32dbg related configuration files and tips.

### `scylla_hide.ini`

The ScyllaHide config should keep the anti-debug off your back. The x32dbg `*.1337` patch files are for xlive.dll version 3.5.95.0 with the SHA-256 hash `8AE328CC7E9F22A8ED1B63F7F0C4977E36BC6C7F7582F1B8E41F1FDF960D5796`.

### `xlive.dll.no_pe_verify_hash.1337`

This neutralizes the `PEVerifyHash` check (the famous `8B FF 55 8B EC 83 EC 20 53 56 57 8D 45 E0 33 F6 50 FF 75 0C 8B F9` signature) which should let you put breakpoints in more places without getting killed. There are countless other checks for IAT, headers, etc..., but this gets you 99% of the way there. If you need to modify other parts of the image then it's pretty easy to cross reference the `PEVerify*` symbols from a dll with a pdb and nop those out.

### `xlive.dll.no_cat_root_check.1337`

This disables the check that the catalog file signature chains back to one of the embedded Microsoft roots, allowing self-signed catalog files. The catalog still needs to be valid, but it doesn't need to be signed by Microsoft. There is more information about catalog files in the notes section.

### `xlive.dll.no_cat_hash_check.1337`

This disables the check that the file hashes match the ones in the catalog, allowing the modification of signed files on disk. The catalog still needs to be valid, but it doesn't need to contain correct hashes.

### Exceptions

You'll want exceptions set to Break On: Second Chance, Logging: Log exception, Exception handled by: Debuggee, since xlive uses SEH to catch divisions by zero and access violations it causes on purpose. Even with this and the patches, you will still sometimes die when single stepping or running until return due to the SEH stuff, you can patch that out or just put a breakpoint somewhere after it so you don't need to single step. But be careful not to put a breakpoint directly after a call into WARBIRD since those bytes need to be unchanged to function properly. The same caution applies to hooking functions that might begin with a call to WARBIRD, like the dll exports, since relocating the call instruction is likely to break it, because WARBIRD uses the return address to find the bytes directly after the call.

## Scripts

The scripts are mostly scraps from when I was testing stuff while writing xwife. They shouldn't be too useful on their own but I've included them anyway in case someone finds them helpful. The dll emulation scripts are for the peacestoned xlive 1.2.241.0 (more info in the next section, use my fork). The frida agents are for xlive 3.5.95.0 and assume ScyllaHide is already doing its job (more info in the previous section).

## Notes

### Microsoft WARBIRD

Microsoft WARBIRD is a code obfuscator used on xlive. The older versions aren't the worst thing in the world and several tools exist to deobfuscate the protected code: [peacestone](https://github.com/UMSKT/peacestone) and [warturd](https://gitlab.com/GlitchyScripts/xlln-modules/-/tree/master/xlln-modules/xlln-warturd?ref_type=heads). I haven't looked at the newer versions at all, but I can't imagine it's too much of a step up. I chose to [modify peacestone](https://github.com/widberg/peacestone) (with help from WitherOrNot and cross referencing warturd) to work better on xlive 1.2.241.0. Since Microsoft can't change the crypto or file formats without breaking everyone's stuff we're lucky that we can reverse engineer the old dlls and it will "just work" with the new dlls. No need to deal with newer WARBIRD versions!

### Syncrosoft MCFACT

For some reason Microsoft decided that they wanted to protect `XLiveProtectData` and `XLiveUnprotectData` with Syncrosoft MCFACT. Nothing else in the dll uses this from what I can tell. It's really annoying. A few comments across hacker news and reddit have mentioned it ([1](https://news.ycombinator.com/item?id=1157262), [2](https://www.reddit.com/r/gaming/comments/bu69y/comment/c0okhji/), [3](https://www.reddit.com/r/IAmA/s/uZbZ1iwSyg)), but I couldn't find much beyond that, I guess it wasn't that popular. I'd never heard of it before.

This [Syncrosoft MCFACT PowerPoint](http://re-trust.dit.unitn.it/files/20080311Doc/harder-Syncrosoft-MCFACT.pdf) from the Re-trust Sixth Quarterly Meeting (March 11, 2008) is the holy grail. It details how it works and shows code snippets. Unfortunately MCFACT is pretty good and I believe them when they say it can't be decomposed. So I just yanked the lookup tables and driver code out of the dll wholesale.

### Protected/Secure Buffer

A lot of the sensitive internal functions take byte array arguments in the form of a protected/secure buffer. Types like `SB_PTR<unsigned char>` (secure buffer pointer), `__SecureBufferHandleStruct *`, and `CSBPseudoPtr` (C small buffer pseudo pointer) are frequently seen around this code. The general idea is to make it harder to find/peek/poke the contents of these arrays in memory, shocker.

In `XLiveInitialize` a number derived from the tick count is stored on the heap and remains constant until it is deallocated in `XLiveUninitialize`. `__SecureBufferHandleStruct *` is a pointer to a `CSBPseudoPtr` that has had the constant added to it. It is then subtracted every time it is accessed. `CSBPseudoPtr` has a mechanism to, instead of storing the array value directly, store two arrays with values that XOR together to make the original array value. This means that all accesses to these arrays have to flow through functions like `SBufferGetByte` and `SBufferSetByte`.

This is the mechanism behind `XLIVE_PROTECTED_BUFFER` (which is just a type erased `__SecureBufferHandleStruct *`) and the associated exports: `XLivePBufferAllocate`, `XLivePBufferFree`, `XLivePBufferGetByte`, `XLivePBufferSetByte`, `XLivePBufferGetDWORD`, `XLivePBufferSetDWORD`, `XLivePBufferGetByteArray`, and `XLivePBufferSetByteArray`.

### AES Whitebox

The AES block cypher code is a "whitebox" implementation, if you even want to call it that. They just bake the primitives and round keys into lookup tables instead of doing it procedurally. Since the AES functions all use the secure buffer construct it is trivial to hook the get/set functions and trace the whole data flow. It only takes at most 3 of these traces to pin every round key.

This whitebox isn't MCFACT, it's their own thing. I don't know why they decided to do their own thing when MCFACT advertises a comprehensive cryptography toolbox that includes AES, but maybe that wasn't available at the time, I'm not certain on the timeline.

### Why do the AES Keys Look Like That?

`g_pcbcSystemLink` uses standard AES-128. Its round keys really are the output of a normal AES-128 key schedule, and that schedule is invertible, so you can run it backwards from any complete round key and collapse them all into a single 16-byte master key. I did exactly that and compared it with the known Xbox 360 key and it matched.

`g_pcbcObfuscation`, `g_pcbcXLiveDRM`, and `g_pcbcXLiveUserData` are a different story. They use a non-standard number of rounds and none of their round key transitions follow the schedule, so there's nothing to invert and no 16-byte master key to collapse them into. None of this is about recovering the keys, the round keys aren't hidden, they're sitting in the lookup tables and I've already extracted them. The only question is whether they compress back down to a smaller master key, and for these three they don't. The round keys themselves are the complete key material.

The one thing I can't rule out is that Microsoft cooked them up from some smaller seed with a custom routine instead of the standard schedule. But even if they did, it still wouldn't get you a master key. A key schedule worth using is indistinguishable from random without the seed, so the round keys won't leak it, and whatever seed existed wouldn't be an AES master key you reach by inverting a schedule anyway. Cracking that generator would be its own project, not a matter of squeezing the round keys down a little harder. For the round keys themselves, what we have is everything there is to get.

### Catalog Files

The catalog files, `*.exe.cat`, are generated by [`makecat`](https://learn.microsoft.com/en-us/windows/win32/seccrypto/makecat) from a catalog definition file, `*.exe.cdf`, and signed with [`signtool`](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool). Usually the game's main executable and `Liveconfig` file, `*.exe.cfg`, are signed. But more files can be signed to be checked with `XLiveProtectedVerifyFile`, or the deprecated `XLiveVerifyDataFile`, if the `OriginalXliveTarget` is older than `2.0.0.0`. There are patches in the configs section to skip the catalog checks, but I'll discuss the security anyway because it's fun.

The verification of these catalog files is extraordinarily weak by today's standards. The catalog signature is not verified by the Windows certificate store, instead xlive.dll independently checks if the certificate chains back to one of four embedded Microsoft roots, listed below. Additionally, there is no expiry check, no revocations, and no code signing or other capability checks (basicConstraints, keyUsage, the codeSigning EKU, and the Microsoft "Hydra" licensing extension are all ignored). Finally, the only supported hashing functions are MD5 and SHA-1. This is all intentional and another case of "They can't change anything without breaking old games."

#### Embedded Roots

The four embedded roots are never stored as data. The chain builder reconstructs each one (public key + distinguished name) byte-by-byte on the stack at runtime as an anti-dump measure. `scripts/emulation/dump_keys.py` emulates that builder and recovers them, writing a `*.spki.der` (public key) and `*.dn.der` (full DN) per root plus a `manifest.txt` (bits, exponent, fingerprint, every DN attribute, and the modulus) into `scripts/emulation/keys/`.

| Common Name | Bits | Scope | spki-sha1 |
|---|---|---|---|
| Microsoft Root Authority | 2048 | Public | `4a5c7522aa46bfa4089d39974ebdb4a360f7a01d` |
| Microsoft Root Certificate Authority | 4096 | Public | `0eac826040562797e52513fc2ae10a539559e4a4` |
| Microsoft Corporate Root Authority | 4096 | Internal (ITG) | `f3e8bb77e39eb15bc19641e766b17a5a6a201266` |
| Microsoft Corporate Root CA | 4096 | Internal (ITG) | `230c9886b7bb619150c033b106d5446886f908f8` |

All four use `e = 65537`. The two public roots are ordinary Microsoft trust anchors. The two "Corporate" roots are Microsoft's internal IT (ITG) PKI, which isn't publicly distributed (the `Microsoft Corporate Root Authority` DN even carries `emailAddress=pkit@microsoft.com`, `OU=ITG`). The `spki-sha1` column is a SHA-1 of the whole SubjectPublicKeyInfo (the key plus its algorithm wrapper, not just the key bits), so it's a fingerprint of the dumped key. It equals the real SubjectKeyIdentifier for Microsoft Root Certificate Authority, but the 1997 Microsoft Root Authority cert has no SKI extension and the ITG roots aren't published, so that only holds for the one root. The fingerprints still match the genuine keys regardless, they just aren't all SKIs.

Notably, the Microsoft Root Authority root has a storied history involving Microsoft Terminal Server Licensing Service and [Flame](https://en.wikipedia.org/wiki/Flame_(malware)). This begs the question, "Can we sign our own catalogs?" Possibly, but there's a missing prerequisite. We don't need to forge any certificates like Flame, since we don't need capabilities like code signing. Any old Microsoft Terminal Server Licensing Service key pair and certificate will do; new ones after the restructure resulting from Flame won't work, since they don't chain back to one of the four trusted roots. However, finding one of those is easier said than done, and you can't generate new old ones[.](https://en.wikipedia.org/wiki/Low-background_steel) I tried looking for one online, or an old VM, or physical server for sale that might have one, but it seems unlikely. I'm not going to waste any more time looking for one since it's totally useless (just use the patches), but if you find one please let me know, it would be cool to sign a catalog. Also, don't get too hung up on the Terminal Server, that just seemed the most likely path to succeed, all that really matters is that the certificate meets the requirements, and there could very well be a totally different path out there that I haven't considered.

#### Structural OIDs

These all have to be present for xlive to accept the file as a signed catalog at all.

| OID | Meaning |
|---|---|
| `1.2.840.113549.1.7.2` | PKCS#7 `SignedData` (the catalog's outer `ContentInfo.contentType`) |
| `1.3.6.1.4.1.311.10.1` | Microsoft Certificate Trust List (`encapContentInfo.contentType`) |
| `1.3.6.1.4.1.311.12.1.1` | `szOID_CATALOG_LIST_MEMBER` |
| `1.3.6.1.4.1.311.12.2.1` | `szOID_CATALOG_LIST_NAME_VALUE` (wraps the name-value attributes) |
| `1.3.6.1.4.1.311.12.2.2` | `szOID_CATALOG_NAME_VALUE` / member info |

The catalog must also carry a `LIVECatalogVersion = "1.0"` catalog attribute. It is not itself an OID but a name-value attribute, whose name is the literal `BMPString` `"LIVECatalogVersion"` (stored UTF-16BE, while its `"1.0"` value is UTF-16LE). All such name-value attributes share the single wrapper OID `1.3.6.1.4.1.311.12.2.1` above and are distinguished by their string name, not by distinct OIDs.

Games may also carry an `OSAttr` name-value attribute, e.g. `OSAttr = "2:5.1,2:5.2,2:6.0"`, carried under the same wrapper OID as `LIVECatalogVersion`. Its value is a comma-separated list of `PlatformId:Major.Minor` entries declaring the OS versions the catalog targets: `2` is `VER_PLATFORM_WIN32_NT`, so `5.1` = Windows XP, `5.2` = Server 2003 / XP x64, and `6.0` = Vista / Server 2008. It is purely descriptive metadata written by `makecat`/`signtool` (from the `*.exe.cdf`) and used by the standard `CryptCATAdmin` tooling to pick the right catalog per OS, xlive's own verifier does not gate on it (unlike `LIVECatalogVersion`).

#### Algorithm OIDs

These are the only algorithms the verifier understands, mapped to a CryptoAPI `CALG`. Anything not in this table makes the verify bail with `NTE_BAD_ALGID`. The same table is used both for the catalog's own `SignerInfo` digest and for every certificate's `signatureAlgorithm` in the chain, so MD5 is accepted at every step.

| OID | Meaning | CALG |
|---|---|---|
| `1.3.14.3.2.26` | SHA-1 | `CALG_SHA1` |
| `1.3.14.3.2.18` | SHA family | `CALG_SHA1` |
| `1.2.840.113549.2.5` | MD5 | `CALG_MD5` |
| `1.2.840.113549.1.1.5` | sha1WithRSAEncryption | `CALG_SHA1` |
| `1.3.14.3.2.29` | sha1WithRSASignature | `CALG_SHA1` |
| `1.3.14.3.2.15` | sha/RSA (OIW) | `CALG_SHA1` |
| `1.2.840.113549.1.1.4` | md5WithRSAEncryption | `CALG_MD5` |
| `1.3.14.3.2.3` | md5/RSA (OIW) | `CALG_MD5` |

#### What a Catalog Must Contain To Be Accepted

Pulling the tables above together, here's everything a catalog needs and roughly the order it's checked. It has to be a PKCS#7 SignedData wrapping a Microsoft CTL, with a `LIVECatalogVersion` of "1.0". The covered files need member hashes in the CTL, and those have to be SHA-1. That isn't just `makecat`'s default, it's a hard requirement, since xlive hashes each file with a hardcoded `CALG_SHA1` and looks the result up, so an MD5 or SHA-256 member hash could never match (page hashes are included and are also SHA-1). The SignerInfo's own digest can be SHA-1 or MD5, so the signature can use MD5 even though the member hashes can't. The signed attributes need a messageDigest equal to the hash of the content, the signature has to verify against the signer certificate's own public key, and the chain has to terminate in one of the four embedded roots, with each terminal intermediate verified against the embedded root's key rather than just matched by name.

That last check is the only real gate and the only thing a self-signed catalog can't satisfy. The two catalog patches in the configs section each get around one of the checks here. The `no_cat_hash_check` patch defeats the member hash comparison, which lets you edit the covered files while keeping the original Microsoft signed cat, since the cat itself still verifies and only the file-to-hash check is neutered. The `no_cat_root_check` patch defeats the embedded root check, which lets you re-sign the cat with your own key, since everything else is reproducible with standard `makecat` and `signtool`.

## Other Stuff

* [cxkes.me - XUID Lookup](https://cxkes.me/xbox/xuid) - Online XUID Lookup tool
* [GfWLUtility](https://github.com/InvoxiPlayGames/GfWLUtility) - Utility for working with Games for Windows - LIVE
* [spaday](https://github.com/widberg/spaday) - GFWL/Xbox 360 [SPAFILE](https://free60.org/System-Software/Formats/SPA/) parser
