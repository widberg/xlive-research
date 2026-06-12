function toArrayBuffer(data) {
  if (data instanceof ArrayBuffer) {
    return data;
  }
  if (ArrayBuffer.isView(data)) {
    return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
  }
  throw new TypeError("Expected ArrayBuffer or TypedArray input.");
}

function installXliveApis(
    XeKeysObfuscate,
    XeKeysUnObfuscate
) {
  // int __stdcall XeKeysObfuscate(int one, uint8_t *plain, int plain_size, uint8_t *cypher_1, _DWORD *p_cypher_size)
  const F_XE_KEYS_OBFUSCATE = new NativeFunction(
    XeKeysObfuscate,
    "uint32",
    ["uint32", "pointer", "int32", "pointer", "pointer"],
    "stdcall"
  );
  // int __stdcall XeKeysUnObfuscate(int one, char *cypher, unsigned int cypher_size, char *plain, _DWORD *p_plain_size)
  const F_XE_KEYS_UNOBFUSCATE = new NativeFunction(
    XeKeysUnObfuscate,
    "uint32",
    ["uint32", "pointer", "int32", "pointer", "pointer"],
    "stdcall"
  );

  const SIZE = 0x17C
  const EXTRA = 0x18
  const BLOCK = 0x10
  const CYPHER_CAPACITY = ((SIZE + BLOCK - 1) & ~(BLOCK - 1)) + EXTRA

  function xeKeysObfuscateDetailed(data) {
    var dataBuffer = toArrayBuffer(data);
    var dataSize = dataBuffer.byteLength >>> 0;
    if (dataSize != SIZE) {
      throw new Error("Bad plain size");
    }
    var plain = Memory.alloc(dataBuffer.byteLength)
    plain.writeByteArray(dataBuffer);

    var cypherCapacity = CYPHER_CAPACITY
    var cypher = Memory.alloc(cypherCapacity)
    var p_cypher_size = Memory.alloc(4)
    p_cypher_size.writeU32(cypherCapacity)

    const ret = F_XE_KEYS_OBFUSCATE(1, plain, dataSize, cypher, p_cypher_size)

    var cypherSize = p_cypher_size.readU32()
    var output = cypher.readByteArray(cypherSize)
    return {
        ret: ret,
        size: cypherSize,
        capacity: cypherCapacity,
        data: output
    }
  }

  function xeKeysObfuscateData(data) {
    return xeKeysObfuscateDetailed(data).data
  }

  function xeKeysUnObfuscateDetailed(data) {
    var dataBuffer = toArrayBuffer(data);
    var dataSize = dataBuffer.byteLength >>> 0;
    var cypher = Memory.alloc(dataBuffer.byteLength)
    cypher.writeByteArray(dataBuffer);

    var plainCapacity = SIZE
    var plain = Memory.alloc(plainCapacity)
    var p_plain_size = Memory.alloc(4)
    p_plain_size.writeU32(plainCapacity)

    const ret = F_XE_KEYS_UNOBFUSCATE(1, cypher, dataSize, plain, p_plain_size)

    var plainSize = p_plain_size.readU32()
    var output = plain.readByteArray(plainSize)
    return {
        ret: ret,
        size: plainSize,
        capacity: plainCapacity,
        data: output
    }
  }

  function xeKeysUnObfuscateData(data) {
    return xeKeysUnObfuscateDetailed(data).data;
  }

  globalThis.F_XE_KEYS_OBFUSCATE = F_XE_KEYS_OBFUSCATE;
  globalThis.F_XE_KEYS_UNOBFUSCATE = F_XE_KEYS_UNOBFUSCATE;
  
  globalThis.xeKeysObfuscateDetailed = xeKeysObfuscateDetailed;
  globalThis.xeKeysObfuscateData = xeKeysObfuscateData;
  globalThis.xeKeysUnObfuscateDetailed = xeKeysUnObfuscateDetailed;
  globalThis.xeKeysUnObfuscateData = xeKeysUnObfuscateData;
}

(function main() {
  if (Process.arch !== "ia32") {
    throw new Error("This script expects ia32 FUEL/xlive.");
  }

  const xlive = Process.getModuleByName("xlive.dll");

  const XeKeysObfuscate = xlive.base.add(0x000F803B);
  const XeKeysUnObfuscate = xlive.base.add(0x000F8121);

  installXliveApis(
    XeKeysObfuscate,
    XeKeysUnObfuscate
  );
})();
