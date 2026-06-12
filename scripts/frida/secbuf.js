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
    xLiveSBufferGetByte
) {
  // int __fastcall SBufferGetByte(__SecureBufferHandleStruct *this, unsigned int index)
  const F_XLIVE_S_BUFFER_GET_BYTE = new NativeFunction(
    xLiveSBufferGetByte,
    "uint32",
    ["pointer", "int32"],
    "fastcall"
  );

  function readAllBytes(p_sb, size, filename) {
    // const size = 0x2300;
    // const filename = "xbox-stuff-3/planc/blob.bin";
    // const size = 0x2500;
    // const filename = "xbox-stuff-3/planc/blob2.bin";
    const sb = p_sb.readPointer()
    const bs = new Uint8Array(size);

    for (var i = 0; i < size; ++i) {
      const b = F_XLIVE_S_BUFFER_GET_BYTE(sb, i);
      bs[i] = b & 0xff;
    }

    File.writeAllBytes(filename, bs.buffer);
  }


  globalThis.F_XLIVE_S_BUFFER_GET_BYTE = F_XLIVE_S_BUFFER_GET_BYTE;
  
  globalThis.readAllBytes = readAllBytes;
}

(function main() {
  if (Process.arch !== "ia32") {
    throw new Error("This script expects ia32 FUEL/xlive.");
  }

  const xlive = Process.getModuleByName("xlive.dll");

  const xLiveSBufferGetByte = xlive.base.add(0x001648B3);
  
  installXliveApis(
    xLiveSBufferGetByte
  );

  const p_sbs_offs = [
    0x006716C8,
    0x006716D0,
    0x006716D8,
    0x00671720,
    0x0067170C,
    0x00671728,
    0x00671738,
    0x00671730,
    0x00671744,
    0x0067174C,
    0x00671754,
    0x0067175C,
  ];

  for (var p_sb_off of p_sbs_offs) {
    console.log(p_sb_off)
    var p_sb = xlive.base.add(p_sb_off)
    readAllBytes(p_sb, 0x3000, "xbox-stuff-3/planc/bins/" + p_sb_off + ".bin");
  }
})();
