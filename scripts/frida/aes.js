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
    xLivePanoramaCryptoCBCEncrypt,
    xLivePanoramaCryptoCBCBlockEncrypt,
    xLiveCSBPseudoPtrSecureBufferHandle,
    p_g_pcbcXLiveUserData
) {
  // unsigned int __thiscall PanoramaCryptoCBC::Encrypt(PanoramaCryptoCBC *this, __SecureBufferHandleStruct *plain, int plain_begin, int plain_end, __SecureBufferHandleStruct *cypher, int cypher_begin, int *cypher_end)
  const F_XLIVE_PANORAMA_CRYPTO_CBC_ENCRYPT = new NativeFunction(
    xLivePanoramaCryptoCBCEncrypt,
    "uint32",
    ["pointer", "pointer", "int32", "int32", "pointer", "int32", "pointer"],
    "thiscall"
  );
  // unsigned int __thiscall PanoramaCryptoCBC::BlockEncrypt(PanoramaCryptoCBC *this, __SecureBufferHandleStruct *input, int input_begin, int input_end, __SecureBufferHandleStruct *cypher, int cypher_begin)
  const F_XLIVE_PANORAMA_CRYPTO_CBC_BLOCK_ENCRYPT = new NativeFunction(
    xLivePanoramaCryptoCBCBlockEncrypt,
    "uint32",
    ["pointer", "pointer", "int32", "int32", "pointer", "int32"],
    "thiscall"
  );
  // __SecureBufferHandleStruct *__thiscall CSBPseudoPtr::operator __SecureBufferHandleStruct *(CSBPseudoPtr *this)
  const F_XLIVE_CSB_PSEUDO_PTR_SECURE_BUFFER_HANDLE = new NativeFunction(
    xLiveCSBPseudoPtrSecureBufferHandle,
    "pointer",
    ["pointer"],
    "thiscall"
  );

  function newCSBPseudoPtr(p) {
    const the = Memory.alloc(8);
    the.add(0).writePointer(p)
    the.add(4).writeU32(0)
    return the;
  }

  function newSecureBufferHandle(p) {
    const pseudoPtr = newCSBPseudoPtr(p);
    const handle = F_XLIVE_CSB_PSEUDO_PTR_SECURE_BUFFER_HANDLE(pseudoPtr);
    return {
      handle: handle,
      pseudoPtr: pseudoPtr
    };
  }

  function getg_pcbcXLiveUserData() {
    return p_g_pcbcXLiveUserData.readPointer()
  }

  const SIZE = 0x10;

  function PanoramaCryptoCBCSetInput(the, input) {
    const inputBuffer = toArrayBuffer(input)
    const inputSize = inputBuffer.byteLength >>> 0;
    if (inputSize != SIZE) {
      throw new Error("Bad IV size");
    }
    the.add(4).writeByteArray(inputBuffer)
  }

  function PanoramaCryptoCBCGetInput(the) {
    return the.add(4)
  }

  function PanoramaCryptoCBCSetIV(the, iv) {
    const ivBuffer = toArrayBuffer(iv)
    const ivSize = ivBuffer.byteLength >>> 0;
    if (ivSize != SIZE) {
      throw new Error("Bad IV size");
    }
    the.add(0x2C).writeByteArray(ivBuffer)
  }

  function PanoramaCryptoCBCGetIV(the) {
    return the.add(0x2C)
  }

  function xLiveEncryptDetailed(data, iv) {
    const dataBuffer = toArrayBuffer(data)
    const dataSize = dataBuffer.byteLength >>> 0;
    if (dataSize != SIZE) {
      throw new Error("Bad data size");
    }
    const the = getg_pcbcXLiveUserData();
    PanoramaCryptoCBCSetIV(the, iv)
    const plain = Memory.alloc(SIZE);
    plain.writeByteArray(dataBuffer);
    const plain_buf = newSecureBufferHandle(plain);
    const cypher = Memory.alloc(SIZE);
    const cypher_buf = newSecureBufferHandle(cypher);
    const p_out_size = Memory.alloc(4);
    p_out_size.writeU32(SIZE);
    const ret = F_XLIVE_PANORAMA_CRYPTO_CBC_ENCRYPT(the, plain_buf.handle, 0, SIZE, cypher_buf.handle, 0, p_out_size);
    const output = cypher.readByteArray(SIZE);
    return {
      ret: ret,
      data: output
    }
  }

  function xLiveBlockEncryptDetailed(inp, iv) {
    const the = getg_pcbcXLiveUserData();
    PanoramaCryptoCBCSetInput(the, inp)
    PanoramaCryptoCBCSetIV(the, iv)

    const input = PanoramaCryptoCBCGetInput(the);
    const cypher = PanoramaCryptoCBCGetIV(the);
    console.log(input, cypher)

    const input_buf = newSecureBufferHandle(input);
    const cypher_buf = newSecureBufferHandle(cypher);
    const ret = F_XLIVE_PANORAMA_CRYPTO_CBC_BLOCK_ENCRYPT(the, input_buf.handle, 0, SIZE, cypher_buf.handle, 0);
    const output = cypher.readByteArray(SIZE);
    return {
      ret: ret,
      data: output
    }
  }

  function xLiveEncrypt(data, iv) {
    return xLiveEncryptDetailed(data, iv).data
  }

  function xLiveEncryptZeroIV(data) {
    return xLiveEncrypt(data, new ArrayBuffer(SIZE))
  }

  globalThis.F_XLIVE_PANORAMA_CRYPTO_CBC_ENCRYPT = F_XLIVE_PANORAMA_CRYPTO_CBC_ENCRYPT;
  globalThis.F_XLIVE_PANORAMA_CRYPTO_CBC_BLOCK_ENCRYPT = F_XLIVE_PANORAMA_CRYPTO_CBC_BLOCK_ENCRYPT;
  globalThis.F_XLIVE_CSB_PSEUDO_PTR_SECURE_BUFFER_HANDLE = F_XLIVE_CSB_PSEUDO_PTR_SECURE_BUFFER_HANDLE;
  
  globalThis.xLiveEncryptZeroIV = xLiveEncryptZeroIV;
  globalThis.xLiveEncrypt = xLiveEncrypt;
  globalThis.xLiveEncryptDetailed = xLiveEncryptDetailed;
  globalThis.xLiveBlockEncryptDetailed = xLiveBlockEncryptDetailed;
}

(function main() {
  if (Process.arch !== "ia32") {
    throw new Error("This script expects ia32 FUEL/xlive.");
  }

  const xlive = Process.getModuleByName("xlive.dll");

  const xLivePanoramaCryptoCBCEncrypt = xlive.base.add(0x000F9444);
  const xLivePanoramaCryptoCBCBlockEncrypt = xlive.base.add(0x000F8CFE);
  const xLiveCSBPseudoPtrSecureBufferHandle = xlive.base.add(0x00164A9E);
  // const p_g_pcbcXLiveUserData = xlive.base.add(0x0066E1C4);
  // const p_g_pcbcXLiveUserData = xlive.base.add(0x0066E1BC); // g_pcbcObfuscation
  // const p_g_pcbcXLiveUserData = xlive.base.add(0x0066E1C0); // g_pcbcXLiveDRM
  const p_g_pcbcXLiveUserData = xlive.base.add(0x0066E1C8); // g_pcbcSystemLink

  installXliveApis(
    xLivePanoramaCryptoCBCEncrypt,
    xLivePanoramaCryptoCBCBlockEncrypt,
    xLiveCSBPseudoPtrSecureBufferHandle,
    p_g_pcbcXLiveUserData
  );
})();

// sys
// 0...
// 3d aa c8 80 6b 5e 5f da ff db d2 04 f0 ed 89 20
