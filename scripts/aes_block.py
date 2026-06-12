"""
All three are the same engine, the standard AES round function
(SubBytes, ShiftRows, MixColumns, AddRoundKey), differing only in the number of
rounds and where the round keys come from:

  key id        addr        rounds  round keys
  ------------  ----------  ------  ------------------------------------------------
  system_link   0x005477C0    10    AES-128 key schedule of master  (REAL AES-128)
  user_data     0x006440FB    11    12 INDEPENDENT round keys (no key schedule)
  obfuscation   0x0054D334    11    12 INDEPENDENT round keys (no key schedule)

user_data/obfuscation are NOT standard AES-128 and have no 16-byte master key. They are the
AES round function run as an 11-round SPN with independent subkeys.
The round keys below ARE the complete, irreducible key material.
"""

SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
INV = bytearray(256)
for i, v in enumerate(SBOX): INV[v] = i

def _xt(a):
    a <<= 1
    return (a ^ 0x11b) & 0xff if a & 0x100 else a
def _mul(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        a = _xt(a); b >>= 1
    return r
def _sr(s):  return [s[(i%4)+4*(((i//4)+(i%4))%4)] for i in range(16)]
def _isr(s): return [s[(i%4)+4*(((i//4)-(i%4))%4)] for i in range(16)]
def _mc(s, M):
    o=[0]*16
    for c in range(4):
        col=s[4*c:4*c+4]
        for r in range(4): o[4*c+r]=_mul(M[r][0],col[0])^_mul(M[r][1],col[1])^_mul(M[r][2],col[2])^_mul(M[r][3],col[3])
    return o
def _mix(s):  return _mc(s, [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]])
def _imix(s): return _mc(s, [[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]])

def encrypt(pt, W):
    """W = list of (rounds+1) round keys (16 bytes each). Last round has no MixColumns."""
    nr = len(W) - 1
    s = [pt[i] ^ W[0][i] for i in range(16)]
    for r in range(1, nr):
        s = [SBOX[x] for x in s]; s = _sr(s); s = _mix(s); s = [s[i] ^ W[r][i] for i in range(16)]
    s = [SBOX[x] for x in s]; s = _sr(s); s = [s[i] ^ W[nr][i] for i in range(16)]
    return bytes(s)

def decrypt(ct, W):
    nr = len(W) - 1
    s = [ct[i] ^ W[nr][i] for i in range(16)]; s = _isr(s); s = [INV[x] for x in s]
    for r in range(nr-1, 0, -1):
        s = [s[i] ^ W[r][i] for i in range(16)]; s = _imix(s); s = _isr(s); s = [INV[x] for x in s]
    s = [s[i] ^ W[0][i] for i in range(16)]
    return bytes(s)

def aes128_schedule(key):
    RC=[0,1,2,4,8,16,32,64,128,0x1b,0x36]; W=[list(key)]
    for r in range(1,11):
        w=W[-1]; c=lambda i:[w[4*i+j] for j in range(4)]; w0,w1,w2,w3=c(0),c(1),c(2),c(3)
        t=w3[1:]+w3[:1]; t=[SBOX[x] for x in t]; t[0]^=RC[r]
        n0=[w0[i]^t[i] for i in range(4)]; n1=[w1[i]^n0[i] for i in range(4)]
        n2=[w2[i]^n1[i] for i in range(4)]; n3=[w3[i]^n2[i] for i in range(4)]
        W.append(n0+n1+n2+n3)
    return W

_h = lambda x: list(bytes.fromhex(x))

# round keys per variant
USER_DATA = [  # 11 rounds, 12 independent round keys
 _h("dfa27fabd7cdf87d81b023fd79e031d4"), _h("79606cf30ef2721dd93f8a60588fa99d"),
 _h("216f9849580ff4ba7a4d8677a3720c17"), _h("fbfda58ada923dc3829dc97920903064"),
 _h("83e23c73781f99f9a28da43a20106d43"), _h("e2ac2ad3614e16a019518f59bbdc2b63"),
 _h("9bcc4620b9f69dc7d8b88b67c1e9043e"), _h("7a352f5de1f9697d000f623fd8b7e958"),
 _h("195eed66636bc23b8292ab460f6d382c"), _h("d7dad174ce843c12adeffe292f7d556f"),
 _h("70919039a74b414d69cf7d5fc4208376"), _h("eb5dd619276744d0802c059de9e378c2")]
OBFUSCATION = [  # 11 rounds, 12 independent round keys
 _h("c395f23c0d14b87fe2a569c2db8158ba"), _h("a427b2960ea2627503b6da0ae113b3c8"),
 _h("3a92eb729eb559e4d9690b7edadfd174"), _h("3bcc62bc015e89ce9febd02a3419eea5"),
 _h("eec63fd1d50a5d6dd454d4a34bbf0489"), _h("34eb4916da2d76c70f272baadb73ff09"),
 _h("90ccfb806fe48476b5c9f2b1baeed91b"), _h("619d2612f151dd929e25cbd72bec3966"),
 _h("9102e07df09fc66f01ce1bfd558a9fab"), _h("7e66a6cdef6446b01ffb80df1e359b22"),
 _h("439e0cd93df8aa14d29ceca4cd676c7b"), _h("d352f75958f6c7bf650e6dabb792810f")]
SYSTEM_LINK = aes128_schedule(bytes.fromhex("64fa1ac20fd75807cae674baa3b4787f"))  # 10 rounds, real AES-128

if __name__ == "__main__":
    import os
    KAT = {  # all-zero plaintext -> DLL oracle ciphertext
        "user_data":   "016ac0f8839dcaff59b811a2c94d4f9e",
        "obfuscation": "c2cd4e6ce71fe253fc32e0d28a9ca4be",
        "system_link": "3daac8806b5e5fdaffdbd204f0ed8920",
    }
    for name, W in (("user_data", USER_DATA), ("obfuscation", OBFUSCATION), ("system_link", SYSTEM_LINK)):
        z = encrypt(bytes(16), W).hex()
        rt = all((lambda p: decrypt(encrypt(p, W), W) == p)(os.urandom(16)) for _ in range(2000))
        tag = ""
        if name in KAT:
            tag = "  KAT(zero) " + ("OK" if z == KAT[name] else f"MISMATCH want {KAT[name]}")
        print(f"{name:12s} rounds={len(W)-1:2d}  enc(zero)={z}  round-trip={'OK' if rt else 'FAIL'}{tag}")
