const XLIVE_PROTECT_ORDINAL = 5034;
const XLIVE_UNPROTECT_ORDINAL = 5035;
const XLIVE_CREATE_PROTECTED_DATA_CONTEXT_ORDINAL = 5036;
const XLIVE_CLOSE_PROTECTED_DATA_CONTEXT_ORDINAL = 5038;
const XLIVE_XUSER_GET_XUID_ORDINAL = 5261;
const XLIVE_PROTECTED_DATA_FLAG_OFFLINE_ONLY = 1;
const HRESULT_INSUFFICIENT_BUFFER = 0x8007007a >>> 0;

function findExportByOrdinal(module, ordinal) {
  if (!module) return null;

  const base = module.base;
  const e_lfanew = base.add(0x3c).readS32();
  const nt = base.add(e_lfanew);
  const optional = nt.add(4 + 20);
  const magic = optional.readU16();
  const dataDirOffset = magic === 0x10b ? 0x60 : 0x70;
  const exportRva = optional.add(dataDirOffset).readU32();
  const exportSize = optional.add(dataDirOffset + 4).readU32();
  if (exportRva === 0) return null;

  const exportDir = base.add(exportRva);
  const ordinalBase = exportDir.add(0x10).readU32();
  const numFuncs = exportDir.add(0x14).readU32();
  const funcsRva = exportDir.add(0x1c).readU32();
  const index = ordinal - ordinalBase;
  if (index < 0 || index >= numFuncs) return null;

  const funcs = base.add(funcsRva);
  const fnRva = funcs.add(index * 4).readU32();
  if (fnRva === 0) return null;
  if (fnRva >= exportRva && fnRva < exportRva + exportSize) return null;

  return base.add(fnRva);
}

function hrToHex(hr) {
  return "0x" + (hr >>> 0).toString(16).padStart(8, "0");
}

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
  protectPtr,
  unprotectPtr,
  createContextPtr,
  closeContextPtr,
  xUserGetXuidPtr
) {
  const F_XLIVE_PROTECT_DATA = new NativeFunction(
    protectPtr,
    "uint32",
    ["pointer", "uint32", "pointer", "pointer", "uint32"],
    "stdcall"
  );
  const F_XLIVE_UNPROTECT_DATA = new NativeFunction(
    unprotectPtr,
    "uint32",
    ["pointer", "uint32", "pointer", "pointer", "pointer"],
    "stdcall"
  );
  const F_XLIVE_CREATE_PROTECTED_DATA_CONTEXT = new NativeFunction(
    createContextPtr,
    "uint32",
    ["pointer", "pointer"],
    "stdcall"
  );
  const F_XLIVE_CLOSE_PROTECTED_DATA_CONTEXT = new NativeFunction(
    closeContextPtr,
    "uint32",
    ["uint32"],
    "stdcall"
  );
  const F_XUSER_GET_XUID = new NativeFunction(
    xUserGetXuidPtr,
    "uint32",
    ["uint32", "pointer"],
    "stdcall"
  );

  function formatXuidHex(xuidHigh, xuidLow) {
    return (
      "0x" +
      (xuidHigh >>> 0).toString(16).padStart(8, "0") +
      (xuidLow >>> 0).toString(16).padStart(8, "0")
    );
  }

  function xLiveCreateProtectedDataContextDetailed(dwFlags) {
    const flags = (
      dwFlags === undefined
        ? XLIVE_PROTECTED_DATA_FLAG_OFFLINE_ONLY
        : dwFlags
    ) >>> 0;

    const pInfo = Memory.alloc(8);
    pInfo.writeU32(8);
    pInfo.add(4).writeU32(flags);

    const pHandleOut = Memory.alloc(Process.pointerSize);
    pHandleOut.writeU32(0);

    const hrData = F_XLIVE_CREATE_PROTECTED_DATA_CONTEXT(pInfo, pHandleOut) >>> 0;
    const handle = pHandleOut.readU32() >>> 0;

    return {
      hrData: hrData,
      hrDataHex: hrToHex(hrData),
      flags: flags,
      handle: handle,
    };
  }

  function xLiveCreateProtectedDataContext(dwFlags) {
    const result = xLiveCreateProtectedDataContextDetailed(dwFlags);
    if (result.hrData !== 0 || result.handle === 0) {
      throw new Error(
        "XLiveCreateProtectedDataContext failed: " +
        result.hrDataHex +
        " handle=0x" +
        result.handle.toString(16)
      );
    }
    return result.handle;
  }

  function xLiveCloseProtectedDataContext(handle) {
    return F_XLIVE_CLOSE_PROTECTED_DATA_CONTEXT(handle >>> 0) >>> 0;
  }

  function xUserGetXuidDetailed(dwUserIndex) {
    const userIndex = (dwUserIndex === undefined ? 0 : dwUserIndex) >>> 0;
    const pXuidOut = Memory.alloc(8);
    pXuidOut.writeU32(0);
    pXuidOut.add(4).writeU32(0);

    const hrData = F_XUSER_GET_XUID(userIndex, pXuidOut) >>> 0;
    const xuidLow = pXuidOut.readU32() >>> 0;
    const xuidHigh = pXuidOut.add(4).readU32() >>> 0;
    const xuidHex = formatXuidHex(xuidHigh, xuidLow);

    let xuidDecimal = null;
    if (typeof BigInt === "function") {
      xuidDecimal = ((BigInt(xuidHigh) << 32n) | BigInt(xuidLow)).toString(10);
    }

    return {
      hrData: hrData,
      hrDataHex: hrToHex(hrData),
      userIndex: userIndex,
      xuidLow: xuidLow,
      xuidHigh: xuidHigh,
      xuidHex: xuidHex,
      xuidDecimal: xuidDecimal,
    };
  }

  function xUserGetXuid(dwUserIndex) {
    const result = xUserGetXuidDetailed(dwUserIndex);
    if (result.hrData !== 0) {
      throw new Error("XUserGetXUID failed: " + result.hrDataHex);
    }
    return result.xuidHex;
  }

  function xLiveProtectDataDetailed(
    dataUnprotected,
    protectedDataHandle,
    contextFlags,
    autoCloseContext
  ) {
    const inputBuffer = toArrayBuffer(dataUnprotected);
    const inputSize = inputBuffer.byteLength >>> 0;
    let handle = (protectedDataHandle === undefined ? 0 : protectedDataHandle) >>> 0;
    let createdContext = false;
    let createResult = null;
    let hrClose = null;

    if (handle === 0) {
      createResult = xLiveCreateProtectedDataContextDetailed(contextFlags);
      if (createResult.hrData !== 0 || createResult.handle === 0) {
        throw new Error(
          "XLiveCreateProtectedDataContext failed before protect: " +
          createResult.hrDataHex +
          " handle=0x" +
          createResult.handle.toString(16)
        );
      }
      handle = createResult.handle >>> 0;
      createdContext = true;
    }

    const shouldAutoClose = autoCloseContext === undefined ? createdContext : !!autoCloseContext;

    const pIn = Memory.alloc(Math.max(1, inputSize));
    if (inputSize !== 0) {
      pIn.writeByteArray(inputBuffer);
    }

    const pOutSize = Memory.alloc(4);
    pOutSize.writeU32(0);

    let hrProbe = 0;
    let hrData = 0;
    let outSize = 0;
    let output = null;

    try {
      hrProbe = F_XLIVE_PROTECT_DATA(
        pIn,
        inputSize,
        ptr(0),
        pOutSize,
        handle
      ) >>> 0;
      let neededSize = pOutSize.readU32() >>> 0;

      if (hrProbe !== 0 && hrProbe !== HRESULT_INSUFFICIENT_BUFFER) {
        throw new Error(
          "XLiveProtectData probe failed: " +
          hrToHex(hrProbe) +
          " neededSize=" +
          neededSize
        );
      }

      if (neededSize === 0) {
        neededSize = 1;
      }

      const pOut = Memory.alloc(neededSize);
      pOutSize.writeU32(neededSize);
      hrData = F_XLIVE_PROTECT_DATA(
        pIn,
        inputSize,
        pOut,
        pOutSize,
        handle
      ) >>> 0;
      outSize = pOutSize.readU32() >>> 0;

      if (hrData !== 0) {
        throw new Error(
          "XLiveProtectData failed: " +
          hrToHex(hrData) +
          " probe=" +
          hrToHex(hrProbe) +
          " outSize=" +
          outSize
        );
      }

      output = outSize === 0 ? new ArrayBuffer(0) : pOut.readByteArray(outSize);
      if (output === null) {
        throw new Error("XLiveProtectData returned unreadable output buffer.");
      }
    } finally {
      if (shouldAutoClose && handle !== 0) {
        hrClose = xLiveCloseProtectedDataContext(handle);
      }
    }

    return {
      hrProbe: hrProbe,
      hrProbeHex: hrToHex(hrProbe),
      hrData: hrData,
      hrDataHex: hrToHex(hrData),
      hrCreate: createResult === null ? null : createResult.hrData,
      hrCreateHex: createResult === null ? null : createResult.hrDataHex,
      hrClose: hrClose,
      hrCloseHex: hrClose === null ? null : hrToHex(hrClose),
      inputSize: inputSize,
      outSize: outSize,
      contextHandle: handle,
      createdContext: createdContext,
      data: output,
    };
  }

  function xLiveProtectData(dataUnprotected, protectedDataHandle, contextFlags, autoCloseContext) {
    return xLiveProtectDataDetailed(
      dataUnprotected,
      protectedDataHandle,
      contextFlags,
      autoCloseContext
    ).data;
  }

  function xLiveUnprotectDataDetailed(
    dataProtected,
    protectedDataHandle,
    autoCloseContext,
    contextFlags
  ) {
    const inputBuffer = toArrayBuffer(dataProtected);
    const inputSize = inputBuffer.byteLength >>> 0;
    let handleIn = (protectedDataHandle === undefined ? 0 : protectedDataHandle) >>> 0;
    let createdContext = false;
    let createResult = null;

    if (handleIn === 0) {
      createResult = xLiveCreateProtectedDataContextDetailed(contextFlags);
      if (createResult.hrData !== 0 || createResult.handle === 0) {
        throw new Error(
          "XLiveCreateProtectedDataContext failed before unprotect: " +
          createResult.hrDataHex +
          " handle=0x" +
          createResult.handle.toString(16)
        );
      }
      handleIn = createResult.handle >>> 0;
      createdContext = true;
    }

    const shouldAutoClose = autoCloseContext === undefined ? createdContext : !!autoCloseContext;

    const pIn = Memory.alloc(Math.max(1, inputSize));
    if (inputSize !== 0) {
      pIn.writeByteArray(inputBuffer);
    }

    const pOutSize = Memory.alloc(4);
    pOutSize.writeU32(0);

    const pCtxHandle = Memory.alloc(Process.pointerSize);
    pCtxHandle.writeU32(handleIn);

    let hrProbe = 0;
    let hrData = 0;
    let outSize = 0;
    let output = null;
    let ctxHandle = 0;
    let hrClose = null;

    try {
      hrProbe = F_XLIVE_UNPROTECT_DATA(
        pIn,
        inputSize,
        ptr(0),
        pOutSize,
        pCtxHandle
      ) >>> 0;
      let neededSize = pOutSize.readU32() >>> 0;

      if (hrProbe !== 0 && hrProbe !== HRESULT_INSUFFICIENT_BUFFER) {
        throw new Error(
          "XLiveUnprotectData probe failed: " +
          hrToHex(hrProbe) +
          " neededSize=" +
          neededSize
        );
      }

      if (neededSize === 0) {
        neededSize = 1;
      }

      const pOut = Memory.alloc(neededSize);
      pOutSize.writeU32(neededSize);
      pCtxHandle.writeU32(handleIn);

      hrData = F_XLIVE_UNPROTECT_DATA(
        pIn,
        inputSize,
        pOut,
        pOutSize,
        pCtxHandle
      ) >>> 0;
      outSize = pOutSize.readU32() >>> 0;
      ctxHandle = pCtxHandle.readU32() >>> 0;

      if (hrData !== 0) {
        throw new Error(
          "XLiveUnprotectData failed: " +
          hrToHex(hrData) +
          " probe=" +
          hrToHex(hrProbe) +
          " outSize=" +
          outSize +
          " ctxHandle=0x" +
          ctxHandle.toString(16)
        );
      }

      output = outSize === 0 ? new ArrayBuffer(0) : pOut.readByteArray(outSize);
      if (output === null) {
        throw new Error("XLiveUnprotectData returned unreadable output buffer.");
      }
    } finally {
      if (shouldAutoClose) {
        const closeHandle = ctxHandle !== 0 ? ctxHandle : handleIn;
        if (closeHandle !== 0) {
          hrClose = xLiveCloseProtectedDataContext(closeHandle);
        }
      }
    }

    return {
      hrProbe: hrProbe,
      hrProbeHex: hrToHex(hrProbe),
      hrData: hrData,
      hrDataHex: hrToHex(hrData),
      hrCreate: createResult === null ? null : createResult.hrData,
      hrCreateHex: createResult === null ? null : createResult.hrDataHex,
      hrClose: hrClose,
      hrCloseHex: hrClose === null ? null : hrToHex(hrClose),
      inputSize: inputSize,
      outSize: outSize,
      contextHandleIn: handleIn,
      contextHandleOut: ctxHandle,
      createdContext: createdContext,
      data: output,
    };
  }

  function xLiveUnprotectData(dataProtected, protectedDataHandle, autoCloseContext, contextFlags) {
    return xLiveUnprotectDataDetailed(
      dataProtected,
      protectedDataHandle,
      autoCloseContext,
      contextFlags
    ).data;
  }

  globalThis.F_XLIVE_PROTECT_DATA = F_XLIVE_PROTECT_DATA;
  globalThis.F_XLIVE_UNPROTECT_DATA = F_XLIVE_UNPROTECT_DATA;
  globalThis.F_XLIVE_CREATE_PROTECTED_DATA_CONTEXT = F_XLIVE_CREATE_PROTECTED_DATA_CONTEXT;
  globalThis.F_XLIVE_CLOSE_PROTECTED_DATA_CONTEXT = F_XLIVE_CLOSE_PROTECTED_DATA_CONTEXT;
  globalThis.F_XUSER_GET_XUID = F_XUSER_GET_XUID;
  globalThis.xLiveCreateProtectedDataContext = xLiveCreateProtectedDataContext;
  globalThis.xLiveCreateProtectedDataContextDetailed = xLiveCreateProtectedDataContextDetailed;
  globalThis.xLiveCloseProtectedDataContext = xLiveCloseProtectedDataContext;
  globalThis.xUserGetXuid = xUserGetXuid;
  globalThis.xUserGetXuidDetailed = xUserGetXuidDetailed;
  globalThis.xLiveProtectData = xLiveProtectData;
  globalThis.xLiveProtectDataDetailed = xLiveProtectDataDetailed;
  globalThis.xLiveUnprotectData = xLiveUnprotectData;
  globalThis.xLiveUnprotectDataDetailed = xLiveUnprotectDataDetailed;
}

(function main() {
  if (Process.arch !== "ia32") {
    throw new Error("This script expects ia32 FUEL/xlive.");
  }

  const xlive = Process.getModuleByName("xlive.dll");
  const protectPtr = findExportByOrdinal(xlive, XLIVE_PROTECT_ORDINAL);
  const unprotectPtr = findExportByOrdinal(xlive, XLIVE_UNPROTECT_ORDINAL);
  const createContextPtr = findExportByOrdinal(
    xlive,
    XLIVE_CREATE_PROTECTED_DATA_CONTEXT_ORDINAL
  );
  const closeContextPtr = findExportByOrdinal(
    xlive,
    XLIVE_CLOSE_PROTECTED_DATA_CONTEXT_ORDINAL
  );
  const xUserGetXuidPtr = findExportByOrdinal(
    xlive,
    XLIVE_XUSER_GET_XUID_ORDINAL
  );

  if (
    protectPtr === null ||
    unprotectPtr === null ||
    createContextPtr === null ||
    closeContextPtr === null ||
    xUserGetXuidPtr === null
  ) {
    throw new Error(
      "Could not resolve required xlive ordinals: " +
      XLIVE_PROTECT_ORDINAL +
      "/" +
      XLIVE_UNPROTECT_ORDINAL +
      "/" +
      XLIVE_CREATE_PROTECTED_DATA_CONTEXT_ORDINAL +
      "/" +
      XLIVE_CLOSE_PROTECTED_DATA_CONTEXT_ORDINAL +
      "/" +
      XLIVE_XUSER_GET_XUID_ORDINAL
    );
  }

  installXliveApis(
    protectPtr,
    unprotectPtr,
    createContextPtr,
    closeContextPtr,
    xUserGetXuidPtr
  );
})();
