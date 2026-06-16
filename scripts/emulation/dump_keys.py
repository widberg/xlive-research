"""
Dump the four Microsoft root-CA public keys that xlive's MinCrypt chain builder
constructs byte-by-byte on the stack (anti-dump) inside fcn.00DB59D7.

Instead of statically reconstructing the scrambled imm/word/dword/register stores
(which is error-prone), we just *run* the builder under DumbEmu and read the
finished stack frame. We stop at 0xDB9945, the instruction right before the
comparison dispatch, by which point both the key/DN blobs and the pairing
table are fully populated (the comparison loops that follow read that table).

Pairing table entry (stride 0x14), recovered from the comparison loops:
    +0x00 keylen   +0x04 keyptr   +0x08 namelen   +0x0C nameptr   +0x10 extra

For every embedded SubjectPublicKeyInfo (found by its rsaEncryption algid marker)
we find its pointer in the table, read the paired Distinguished Name, pull the CN
out of it, and write the key out named by that CN. One run dumps all four.

Usage:  python dump_keys.py <path-to-xlive_..._stoned.dll>
"""
import argparse
import hashlib
import os
import re
import struct
from pathlib import Path

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")

from dumbemu import DumbEmu
from unicorn import UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED

ANCHOR_BUILDER = 0x00DB59D7       # fcn.00DB59D7 (thunked via 0x50A347)
STOP_AFTER_BUILD = 0x00DB9945     # build + pairing table done, before compare loops
PYTHON_MALLOC = 0x0048F1FC        # cdecl malloc(size) -> ptr
PYTHON_FREE = 0x0048F13A          # stdcall free(ptr) -> void

FRAME_LO = 0x0A00                 # bytes below ebp to capture
FRAME_HI = 0x0140                 # bytes above ebp to capture

# AlgorithmIdentifier for rsaEncryption: SEQ{ OID 1.2.840.113549.1.1.1, NULL }
RSA_ALGID = bytes.fromhex("300d06092a864886f70d0101010500")
CN_OID = bytes.fromhex("0603550403")     # OID 2.5.4.3 = commonName (id-at-commonName)

# Friendly names for the attribute OIDs that show up in these roots' DNs.
OID_NAMES = {
    "2.5.4.3": "CN", "2.5.4.4": "SN", "2.5.4.5": "serialNumber",
    "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.9": "street",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.12": "title",
    "2.5.4.42": "GN", "2.5.4.43": "initials",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.1": "UID",
    "0.9.2342.19200300.100.1.25": "DC",
}


def decode_oid(b):
    """Decode DER OID content bytes (no tag/len) to dotted-decimal text."""
    if not b:
        return ""
    out = [str(b[0] // 40), str(b[0] % 40)]
    val = 0
    for c in b[1:]:
        val = (val << 7) | (c & 0x7F)
        if not (c & 0x80):
            out.append(str(val))
            val = 0
    return ".".join(out)


def decode_str(tag, raw):
    """Decode a DER directory-string value to text (BMPString is UTF-16BE)."""
    if tag == 0x1E:                       # BMPString
        return raw.decode("utf-16-be", "replace").strip()
    try:
        return raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return raw.decode("latin1").strip()


def iter_tlv(buf, start, end):
    """Yield (tag, value_start, value_len) for each DER TLV in buf[start:end]."""
    i = start
    while i + 2 <= end:
        tag = buf[i]
        vlen, hs = parse_der_len(buf, i + 1)
        vs = i + 1 + hs
        if vs + vlen > end:
            break
        yield tag, vs, vlen
        i = vs + vlen


def hook_passthrough_malloc(emu):
    def cb(uc, addr):
        esp = emu.regs.read(emu.regs.sp)
        ret = emu.struct.read(esp, "I")[0]
        size = emu.struct.read(esp + 4, "I")[0] & 0xFFFFFFFF
        emu.regs.write(emu.regs.ret, emu.malloc(size or 1) & 0xFFFFFFFF)
        emu.regs.write(emu.regs.sp, esp + 4)
        emu.regs.write(emu.regs.ip, ret)
    return cb


def hook_passthrough_free(emu):
    def cb(uc, addr):
        esp = emu.regs.read(emu.regs.sp)
        ret = emu.struct.read(esp, "I")[0]
        ptr = emu.struct.read(esp + 4, "I")[0] & 0xFFFFFFFF
        if ptr:
            emu.free(ptr)
        emu.regs.write(emu.regs.ret, 0)
        emu.regs.write(emu.regs.sp, esp + 8)
        emu.regs.write(emu.regs.ip, ret)
    return cb


def on_unmapped(emu, kind):
    def cb(uc, access, address, size, value, user_data):
        ip = emu.regs.read(emu.regs.ip)
        print(f"  unmapped {kind}: addr=0x{address:08X} ip=0x{ip:08X}")
        return False
    return cb


def parse_der_len(buf, i):
    """Return (length, header_size) for a DER TLV whose length byte is at buf[i]."""
    b = buf[i]
    if b < 0x80:
        return b, 1
    n = b & 0x7F
    return int.from_bytes(buf[i + 1:i + 1 + n], "big"), 1 + n


def extract_spkis(frame, base_addr):
    """Find every SubjectPublicKeyInfo in the frame; return [(addr, der, modulus_hex)]."""
    out = []
    for m in re.finditer(re.escape(RSA_ALGID), frame):
        algid = m.start()
        # SPKI outer SEQUENCE begins just before the algid (30 82 LL LL  <algid> ...)
        start = algid - 4
        if start < 0 or frame[start] != 0x30 or frame[start + 1] != 0x82:
            continue
        total = (frame[start + 2] << 8 | frame[start + 3]) + 4
        der = frame[start:start + total]
        # modulus: INTEGER right after the BIT STRING/inner SEQ -> 02 82 LL LL 00 <mod>
        mi = der.find(b"\x02\x82")
        modulus = ""
        if mi >= 0:
            mlen, hs = parse_der_len(der, mi + 1)
            mod = der[mi + 1 + hs: mi + 1 + hs + mlen]
            modulus = mod.lstrip(b"\x00").hex()
        out.append((base_addr + start, der, modulus))
    return out


def find_table_entry(frame, base_addr, key_addr, key_len):
    """Locate the pairing-table slot whose key-pointer points into this key, then
    return the (namelen, nameptr, dn_bytes) of the DN paired with it in that entry.

    Entry is 5 dwords (stride 0x14): one {len,ptr} pair points at the key, the
    other at the DN. We don't assume which slot is which, we find the key
    pointer, then try both candidate DN slots and accept the one whose target
    actually contains the commonName OID."""
    u32 = lambda o: struct.unpack_from("<I", frame, o)[0]
    fend = base_addr + len(frame)
    for P in range(0, len(frame) - 4, 4):
        ptr = u32(P)
        if not (key_addr <= ptr < key_addr + key_len):
            continue
        # key-ptr sits at entry+0x04 or entry+0x0C; the DN {len,ptr} is the other pair.
        for nl_off, np_off in ((P + 4, P + 8), (P - 0xC, P - 8)):
            if nl_off < 0 or np_off < 0 or np_off + 4 > len(frame):
                continue
            namelen, nameptr = u32(nl_off), u32(np_off)
            if not (0 < namelen < 0x400 and base_addr <= nameptr < fend - namelen):
                continue
            dn = frame[nameptr - base_addr: nameptr - base_addr + namelen]
            if CN_OID in dn:
                return namelen, nameptr, dn
    return None


def parse_name(dn):
    """Parse an X.500 Name DER blob into an ordered list of (oid, label, value).

    Name ::= SEQUENCE OF RDN; RDN ::= SET OF AttributeTypeAndValue;
    AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }. Returns every
    attribute (CN, O, OU, emailAddress, DC, ...) in DER order."""
    if not dn or dn[0] != 0x30:
        return []
    seqlen, hs = parse_der_len(dn, 1)
    attrs = []
    for rdn_tag, rs, rl in iter_tlv(dn, 1 + hs, 1 + hs + seqlen):   # each RDN (SET)
        for atv_tag, avs, avl in iter_tlv(dn, rs, rs + rl):         # each ATV (SEQUENCE)
            parts = list(iter_tlv(dn, avs, avs + avl))
            if len(parts) < 2:
                continue
            (_, ovs, ovl), (vtag, vvs, vvl) = parts[0], parts[1]
            oid = decode_oid(dn[ovs:ovs + ovl])
            attrs.append((oid, OID_NAMES.get(oid, oid), decode_str(vtag, dn[vvs:vvs + vvl])))
    return attrs


def dn_text(attrs):
    """Render parsed DN attributes as a single comma-separated RFC-4514-ish string."""
    return ", ".join(f"{label}={value}" for _, label, value in attrs)


def cn_of(attrs):
    for oid, label, value in attrs:
        if oid == "2.5.4.3":
            return value
    return None


def spki_details(der):
    """From a SubjectPublicKeyInfo DER, return (modulus_hex, exponent, bits, spki_sha1).

    spki_sha1 = SHA-1 over the whole SubjectPublicKeyInfo, a key fingerprint.
    Only the SPKI and DN are reconstructed on the stack (there is no full cert,
    hence no actual SubjectKeyIdentifier extension to read). For the two *public*
    roots (Microsoft Root Authority, Microsoft Root Certificate Authority) this
    fingerprint matches the SKI in their publicly distributed certs; the two
    internal 'Corporate' (ITG) roots are not published, so there is nothing
    external to compare against."""
    modulus = exponent = ""
    bits = 0
    spki_sha1 = hashlib.sha1(der).hexdigest() if der else ""
    # SPKI ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    if der and der[0] == 0x30:
        seqlen, hs = parse_der_len(der, 1)
        for tag, vs, vl in iter_tlv(der, 1 + hs, 1 + hs + seqlen):
            if tag != 0x03:                       # BIT STRING subjectPublicKey
                continue
            key_der = der[vs + 1: vs + vl]        # drop the unused-bits octet
            # RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
            if key_der and key_der[0] == 0x30:
                klen, khs = parse_der_len(key_der, 1)
                ints = [t for t in iter_tlv(key_der, 1 + khs, 1 + khs + klen) if t[0] == 0x02]
                if len(ints) >= 2:
                    mod = key_der[ints[0][1]: ints[0][1] + ints[0][2]].lstrip(b"\x00")
                    exp = key_der[ints[1][1]: ints[1][1] + ints[1][2]].lstrip(b"\x00")
                    modulus = mod.hex()
                    bits = len(mod) * 8
                    exponent = str(int.from_bytes(exp, "big")) if exp else ""
    return modulus, exponent, bits, spki_sha1


def sanitize(name):
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_")


def main():
    ap = argparse.ArgumentParser(description="Dump the embedded MinCrypt root keys via DumbEmu.")
    ap.add_argument("dll_path", type=Path)
    args = ap.parse_args()

    out_dir = Path(__file__).resolve().parent / "keys"
    out_dir.mkdir(exist_ok=True)
    dll_path = args.dll_path.expanduser().resolve()

    emu = DumbEmu(str(dll_path))
    emu.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, on_unmapped(emu, "read"))
    emu.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, on_unmapped(emu, "write"))
    emu.hook(PYTHON_MALLOC, hook_passthrough_malloc(emu))
    emu.hook(PYTHON_FREE, hook_passthrough_free(emu))

    # Run the builder, stopping once the table+blobs are fully built.
    print(f"running builder 0x{ANCHOR_BUILDER:08X} -> stop 0x{STOP_AFTER_BUILD:08X}")
    emu.call(ANCHOR_BUILDER, STOP_AFTER_BUILD, 0, 0)

    ip = emu.regs.read(emu.regs.ip) & 0xFFFFFFFF
    esp = emu.regs.read(emu.regs.sp) & 0xFFFFFFFF
    ebp = emu.regs.read("ebp") & 0xFFFFFFFF
    print(f"stopped ip=0x{ip:08X}  esp=0x{esp:08X}  ebp=0x{ebp:08X}")
    # locals (keys/DNs/pairing table) live around ebp: some DN blobs are stored
    # a little ABOVE ebp (e.g. ebp+0x24), so capture past it, but below esp and
    # above the stack top (0x10000000) is unmapped, so clamp the top.
    base = (esp & ~0xF) - 0x10
    top = ebp + 0x80
    while top > base:
        try:
            frame = bytes(emu.mem.read(base, top - base))
            break
        except Exception:
            top -= 0x10
    else:
        raise RuntimeError("could not read stack frame")
    print(f"captured frame 0x{base:08X}..0x{base + len(frame):08X} ({len(frame)} bytes)")

    spkis = extract_spkis(frame, base)
    print(f"found {len(spkis)} embedded public key(s)\n")

    manifest = []
    for idx, (addr, der, _modulus) in enumerate(spkis):
        entry = find_table_entry(frame, base, addr, len(der))
        dn = entry[2] if entry is not None else b""
        attrs = parse_name(dn)
        name = cn_of(attrs) or f"root_{idx}"
        modulus, exponent, bits, spki_sha1 = spki_details(der)

        stem = sanitize(name)
        spki_fn = out_dir / f"{stem}.spki.der"
        spki_fn.write_bytes(der)
        dn_fn = None
        if dn:
            dn_fn = out_dir / f"{stem}.dn.der"
            dn_fn.write_bytes(dn)

        manifest.append({
            "name": name, "bits": bits, "exponent": exponent, "spki_sha1": spki_sha1,
            "spki_file": spki_fn.name, "spki_len": len(der),
            "dn_file": dn_fn.name if dn_fn else "", "dn_len": len(dn),
            "dn": dn_text(attrs), "attrs": attrs, "modulus": modulus,
        })

        print(f"[{idx}] {name}  ({bits}-bit, e={exponent})")
        print(f"     spki     : {len(der)} bytes -> {spki_fn.relative_to(out_dir.parent)}")
        if dn_fn:
            print(f"     dn       : {len(dn)} bytes -> {dn_fn.relative_to(out_dir.parent)}")
        print(f"     spki-sha1: {spki_sha1}  (key fingerprint)")
        for oid, label, value in attrs:
            print(f"       {label:>12} ({oid}) = {value}")
        print(f"     mod   : {modulus[:48]}... ({len(modulus) // 2} bytes)")

    lines = []
    for m in manifest:
        lines.append(f"# {m['name']}")
        lines.append(f"bits\t{m['bits']}")
        lines.append(f"exponent\t{m['exponent']}")
        lines.append(f"spki-sha1\t{m['spki_sha1']}\t(SHA-1 of SubjectPublicKeyInfo; key fingerprint)")
        lines.append(f"spki\t{m['spki_file']}\t{m['spki_len']}B")
        lines.append(f"dn\t{m['dn_file']}\t{m['dn_len']}B")
        lines.append(f"dn-string\t{m['dn']}")
        for oid, label, value in m["attrs"]:
            lines.append(f"attr\t{label}\t{oid}\t{value}")
        lines.append(f"modulus\t{m['modulus']}")
        lines.append("")
    (out_dir / "manifest.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nwrote {len(manifest)} key(s) + DNs + manifest.txt to {out_dir}")


if __name__ == "__main__":
    main()
