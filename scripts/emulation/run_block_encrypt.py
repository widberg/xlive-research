import argparse
import os
from pathlib import Path

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")

from dumbemu import DumbEmu
from unicorn import (
    UC_HOOK_CODE,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
)

# AES_USER_DATA = 0x0054D334 # obfuscation
AES_USER_DATA = 0x005477C0 # system
# AES_USER_DATA = 0x006440FB # user data
CSB_PSEUDO_PTR_OPERATOR_SECURE_BUFFER_HANDLE_STRUCT_P = 0x0054C014 # thiscall
PYTHON_MALLOC = 0x0048F1FC # cdecl malloc(size) -> ptr
PYTHON_FREE = 0x0048F13A # stdcall free(ptr) -> void
P_PRNG = 0x008F10D4
S_BUFFER_GET_BYTE = 0x0054BE29 # fastcall
S_BUFFER_SET_BYTE = 0x0054BF8E # fastcall
S_BUFFER_NEW = 0x0054BA05 # stdcall(size) -> sb
S_BUFFER_COPY_BYTE = 0x0054BFC3 # fastcall(dst_sb, dst_index, src_sb, src_index)
S_BUFFER_RESOLVE_BYTE = 0x0054BE59

S_BUFFER_CONTENTS = [
    ("aes_lut_user_data", 0x008F10F4, 0x008F10F8, "bufs/0x008F10F4.bin"),
    ("aes_lut_obfuscate", 0x008F10E4, 0x008F10E8, "bufs/0x008F10E4.bin"),
    ("aes_lut_system_link", 0x008F1114, 0x008F1118, "bufs/0x008F1114.bin"),
    ("aes_lut_system_link_other", 0x008F110C, 0x008F1110, "bins/6756040.bin"),
]

BUFFER_SIZE = 0x10
STOP_ON_JANK = True

def format_trace_hex(value: int):
    return f"{value:X}"

def format_hex_frame(data: bytes):
    return data.hex(" ").upper()

class SBufferTrace:
    def __init__(self, emu: DumbEmu, path: Path):
        self.emu = emu
        self.path = path
        self.lines = []
        self.buffers = {}
        self.csb_names = {}

    def register(self, sb: int, name: str, backing: int):
        self.buffers[sb & 0xFFFFFFFF] = (name, backing)

    def name_csb(self, csb: int, name: str):
        self.csb_names[csb & 0xFFFFFFFF] = name

    def register_csb(self, csb: int, sb: int, backing: int):
        sb &= 0xFFFFFFFF
        name = self.csb_names.pop(csb & 0xFFFFFFFF, None)
        if name is None:
            info = self.get_info(sb)
            name = info[0] if info is not None else f"sb_{sb:08X}"
        self.register(sb, name, backing)

    def get_info(self, sb: int):
        return self.buffers.get(sb & 0xFFFFFFFF)

    def reset(self):
        self.lines.clear()

    def append(self, op: str, name: str, index: int, value: int):
        self.lines.append(
            f"{op} {name} {format_trace_hex(index)} {format_trace_hex(value & 0xFF)}"
        )

    def write(self):
        text = "".join(f"{line}\n" for line in self.lines)
        self.path.write_text(text)

class ExecutionTrace:
    def __init__(self, path: Path):
        self.path = path
        self.lines = []

    def __enter__(self):
        self.lines = []
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.path.write_text("".join(self.lines))
        self.lines = []

    def on_code(self, uc, address, size, user_data):
        self.lines.append(f"0x{address:08X}\n")

def on_unmapped_mem(emu: DumbEmu, kind: str):
    def cb(uc, access, address, size, value, user_data):
        ip = emu.regs.read(emu.regs.ip)
        print(f"unmapped {kind}: addr=0x{address:08X} ip=0x{ip:08X}")
        return False

    return cb

def stop_for_sbuffer_error(emu: DumbEmu, message: str):
    ip = emu.regs.read(emu.regs.ip)
    print(f"secure-buffer trace error: {message} ip=0x{ip:08X}")
    emu.uc.emu_stop()

def hook_sbuffer_get_byte(emu: DumbEmu, trace: SBufferTrace):
    def cb(uc, addr):
        esp = emu.regs.read(emu.regs.sp)
        ret_addr = emu.struct.read(esp, "I")[0]
        sb = emu.regs.read("ecx")
        index = emu.regs.read("edx") & 0xFFFFFFFF
        info = trace.get_info(sb)
        if info is None:
            stop_for_sbuffer_error(emu, f"get untracked sb=0x{sb & 0xFFFFFFFF:08X} index=0x{index:X}")
            return

        name, backing = info
        # get_byte is a plain passthrough: it returns backing[index]. Read the
        # value here, atomically with the index from edx, rather than pairing an
        # index captured at call time with a value captured later at the return
        # site -- that FIFO-per-return-address pairing desyncs when one return
        # address services back-to-back reads, mislabeling an index by a sibling.
        value = emu.mem.read(backing + index, 1)[0]
        trace.append("get", name, index, value)
        emu.regs.write(emu.regs.ret, value)
        emu.regs.write(emu.regs.sp, esp + 4)
        emu.regs.write(emu.regs.ip, ret_addr)

    return cb

def hook_sbuffer_set_byte(emu: DumbEmu, trace: SBufferTrace):
    def cb(uc, addr):
        esp = emu.regs.read(emu.regs.sp)
        ret_addr = emu.struct.read(esp, "I")[0]
        sb = emu.regs.read("ecx")
        index = emu.regs.read("edx") & 0xFFFFFFFF
        info = trace.get_info(sb)
        if info is None:
            stop_for_sbuffer_error(emu, f"set untracked sb=0x{sb & 0xFFFFFFFF:08X} index=0x{index:X}")
            return

        name, backing = info
        value = emu.mem.read(esp + 4, 1)[0]
        emu.mem.write(backing + index, bytes([value]))
        trace.append("set", name, index, value)
        emu.regs.write(emu.regs.ret, value)
        emu.regs.write(emu.regs.sp, esp + 8)
        emu.regs.write(emu.regs.ip, ret_addr)

    return cb

def hook_sbuffer_new(emu: DumbEmu, trace: SBufferTrace = None):
    def cb(uc, addr):
        esp = emu.regs.read(emu.regs.sp)
        ret_addr = emu.struct.read(esp, "I")[0]
        size = emu.struct.read(esp + 4, "I")[0] & 0xFFFFFFFF
        backing = emu.malloc(size)
        sb = new_sb(emu, backing, trace, f"malloc_{size:X}_{backing:08X}")

        emu.regs.write(emu.regs.ret, sb & 0xFFFFFFFF)
        emu.regs.write(emu.regs.sp, esp + 8)
        emu.regs.write(emu.regs.ip, ret_addr)

    return cb

def hook_sbuffer_copy_byte(emu: DumbEmu, trace: SBufferTrace):
    def cb(uc, addr):
        esp = emu.regs.read(emu.regs.sp)
        ret_addr = emu.struct.read(esp, "I")[0]
        dst_sb = emu.regs.read("ecx")
        dst_index = emu.regs.read("edx") & 0xFFFFFFFF
        src_sb = emu.struct.read(esp + 4, "I")[0]
        src_index = emu.struct.read(esp + 8, "I")[0] & 0xFFFFFFFF

        src_info = trace.get_info(src_sb)
        dst_info = trace.get_info(dst_sb)
        if src_info is None:
            stop_for_sbuffer_error(emu, f"copy untracked src sb=0x{src_sb & 0xFFFFFFFF:08X} index=0x{src_index:X}")
            return
        if dst_info is None:
            stop_for_sbuffer_error(emu, f"copy untracked dst sb=0x{dst_sb & 0xFFFFFFFF:08X} index=0x{dst_index:X}")
            return

        src_name, src_backing = src_info
        value = emu.mem.read(src_backing + src_index, 1)[0]
        trace.append("copy get", src_name, src_index, value)

        dst_name, dst_backing = dst_info
        emu.mem.write(dst_backing + dst_index, bytes([value & 0xFF]))
        trace.append("copy set", dst_name, dst_index, value)
        emu.regs.write(emu.regs.ret, value)

        emu.regs.write(emu.regs.sp, esp + 12)
        emu.regs.write(emu.regs.ip, ret_addr)

    return cb

def hook_sbuffer_resolve_byte_error(emu: DumbEmu):
    def cb(uc, addr):
        stop_for_sbuffer_error(emu, "direct call to 0x0054BE59")

    return cb

def hook_python_malloc(emu: DumbEmu):
    def cb(uc, addr):
        esp = emu.regs.read(emu.regs.sp)
        ret_addr = emu.struct.read(esp, "I")[0]
        size = emu.struct.read(esp + 4, "I")[0] & 0xFFFFFFFF
        ptr = emu.malloc(size if size else 1)

        emu.regs.write(emu.regs.ret, ptr & 0xFFFFFFFF)
        emu.regs.write(emu.regs.sp, esp + 4)
        emu.regs.write(emu.regs.ip, ret_addr)
        if ret_addr == emu.ctx.fakeret:
            uc.emu_stop()

    return cb

def hook_python_free(emu: DumbEmu):
    def cb(uc, addr):
        esp = emu.regs.read(emu.regs.sp)
        ret_addr = emu.struct.read(esp, "I")[0]
        ptr = emu.struct.read(esp + 4, "I")[0] & 0xFFFFFFFF
        if ptr:
            emu.free(ptr)

        emu.regs.write(emu.regs.ret, 0)
        emu.regs.write(emu.regs.sp, esp + 8)
        emu.regs.write(emu.regs.ip, ret_addr)
        if ret_addr == emu.ctx.fakeret:
            uc.emu_stop()

    return cb

def read_prng_offset(emu: DumbEmu):
    p_prng = emu.struct.read(P_PRNG, "I")[0]
    return emu.struct.read(p_prng, "I")[0]

def csb_pseudo_ptr_operator_secure_buffer_handle_struct_p(
    emu: DumbEmu, csb: int, trace: SBufferTrace = None
):
    csb &= 0xFFFFFFFF
    backing = emu.struct.read(csb, "I")[0] & 0xFFFFFFFF
    if not backing:
        return 0

    sb = (csb + read_prng_offset(emu)) & 0xFFFFFFFF
    if trace is not None:
        trace.register_csb(csb, sb, backing)
    return sb

def hook_csb_pseudo_ptr_operator_secure_buffer_handle_struct_p(
    emu: DumbEmu, trace: SBufferTrace = None
):
    def cb(uc, addr):
        esp = emu.regs.read(emu.regs.sp)
        ret_addr = emu.struct.read(esp, "I")[0]
        csb = emu.regs.read("ecx") & 0xFFFFFFFF
        sb = csb_pseudo_ptr_operator_secure_buffer_handle_struct_p(emu, csb, trace)

        emu.regs.write(emu.regs.ret, sb)
        emu.regs.write(emu.regs.sp, esp + 4)
        emu.regs.write(emu.regs.ip, ret_addr)
        if ret_addr == emu.ctx.fakeret:
            uc.emu_stop()

    return cb

def init_prng(emu: DumbEmu):
    prng = emu.malloc(4)
    emu.struct.write(prng, "I", 0)
    emu.struct.write(P_PRNG, "I", prng)

def new_csb(emu: DumbEmu, p: int):
    csb = emu.malloc(8)
    emu.struct.write(csb + 0, "I", p)
    emu.struct.write(csb + 4, "I", 0)
    return csb

def new_sb(emu: DumbEmu, p: int, trace: SBufferTrace = None, name: str = None):
    csb = new_csb(emu, p)
    if trace is not None and name is not None:
        trace.name_csb(csb, name)
    return csb_pseudo_ptr_operator_secure_buffer_handle_struct_p(emu, csb, trace)

def new_buf_from_file(emu: DumbEmu, path: Path):
    bs = path.read_bytes()
    p = emu.malloc(len(bs))
    emu.mem.write(p, bs)
    return p

def init_aes_lut(emu: DumbEmu, name: str, blob_path: Path, p_sb: int, p_sb_off: int, trace: SBufferTrace = None):
    blob_p = new_buf_from_file(emu, blob_path)
    sb = new_sb(emu, blob_p, trace, name)
    emu.struct.write(p_sb, "I", sb)
    emu.struct.write(p_sb_off, "I", 0)

def call_thiscall(emu: DumbEmu, fn_addr, breakpoint, this_ptr, *args):
    old_ecx = emu.regs.read("ecx")
    emu.regs.write("ecx", this_ptr)      # hidden this
    try:
        return emu.call(fn_addr, breakpoint, *args)  # do NOT include this_ptr in args
    finally:
        emu.regs.write("ecx", old_ecx)

def call_fastcall(emu: DumbEmu, fn_addr, breakpoint, *args):
    old_ecx = emu.regs.read("ecx")
    old_edx = emu.regs.read("edx")

    if len(args) > 0:
        emu.regs.write("ecx", args[0])
    if len(args) > 1:
        emu.regs.write("edx", args[1])

    try:
        return emu.call(fn_addr, breakpoint, *args[2:])  # first two args are ecx/edx
    finally:
        emu.regs.write("ecx", old_ecx)
        emu.regs.write("edx", old_edx)

def call_reusing_stack(emu: DumbEmu, fn_addr: int, *args, max_insns: int = 1_000_000):
    emu.stack.init(emu.mem, emu.regs)
    emu.regs.write(emu.regs.sp, emu.stack.base)
    sp = emu.regs.prep(
        emu.mem,
        emu.stack.base,
        args,
        shadow=emu.ctx.platform == "windows" and emu.ctx.is_64,
    )
    emu.regs.write(emu.regs.sp, sp)
    emu.uc.emu_start(fn_addr, emu.ctx.fakeret, count=max_insns)
    ip = emu.regs.read(emu.regs.ip)
    if ip != emu.ctx.fakeret:
        raise RuntimeError(f"emulation stopped at 0x{ip:08X}, not fakeret")
    return emu.regs.retval()

def parse_plain_hex(text: str):
    try:
        plain = bytes.fromhex(text)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from e

    if len(plain) != BUFFER_SIZE:
        raise argparse.ArgumentTypeError(
            f"plain must decode to {BUFFER_SIZE} bytes, got {len(plain)}"
        )

    return plain

def parse_random_runs(text: str):
    try:
        count = int(text, 0)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"invalid run count: {text!r}") from e

    if count < 1:
        raise argparse.ArgumentTypeError("random run count must be at least 1")

    return count

def parse_args():
    parser = argparse.ArgumentParser(
        description="Run AES_USER_DATA with a fixed or random plaintext buffer."
    )
    parser.add_argument("dll_path", type=Path)
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--plain",
        metavar="HEX",
        type=parse_plain_hex,
        help=f"{BUFFER_SIZE}-byte plaintext, parsed with bytes.fromhex",
    )
    group.add_argument(
        "--random",
        nargs="?",
        const=1,
        metavar="N",
        type=parse_random_runs,
        help="run N random plaintexts; defaults to 1 when N is omitted",
    )
    parser.add_argument(
        "--execution-trace",
        action="store_true",
        help="write execution.txt instruction trace",
    )
    parser.add_argument(
        "--secure-buffer-trace",
        "--sbuffer-trace",
        dest="sbuffer_trace",
        action="store_true",
        help="write run_trace.txt secure-buffer get/set trace",
    )

    return parser.parse_args()

def print_run_start(run_index: int, plain: bytes):
    print(f"{run_index} plain={plain.hex()} ", end="", flush=True)

def print_result(ret: int, cypher: bytes):
    assert ret == 0
    print(f"cypher={cypher.hex()}")

def main():
    args = parse_args()

    dir_path = Path(__file__).resolve().parent
    dll_path = args.dll_path.expanduser().resolve()

    emu = DumbEmu(str(dll_path))
    emu.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, on_unmapped_mem(emu, "read"))
    emu.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, on_unmapped_mem(emu, "write"))
    trace = SBufferTrace(emu, dir_path / "run_trace.txt") if args.sbuffer_trace else None
    emu.hook(
        CSB_PSEUDO_PTR_OPERATOR_SECURE_BUFFER_HANDLE_STRUCT_P,
        hook_csb_pseudo_ptr_operator_secure_buffer_handle_struct_p(emu, trace),
    )
    emu.hook(PYTHON_MALLOC, hook_python_malloc(emu))
    emu.hook(PYTHON_FREE, hook_python_free(emu))
    emu.hook(S_BUFFER_NEW, hook_sbuffer_new(emu, trace))
    if trace is not None:
        emu.hook(S_BUFFER_GET_BYTE, hook_sbuffer_get_byte(emu, trace))
        emu.hook(S_BUFFER_SET_BYTE, hook_sbuffer_set_byte(emu, trace))
        emu.hook(S_BUFFER_COPY_BYTE, hook_sbuffer_copy_byte(emu, trace))
        emu.hook(S_BUFFER_RESOLVE_BYTE, hook_sbuffer_resolve_byte_error(emu))
    init_prng(emu)
    for (name, p_sb, p_sb_off, blob_path) in S_BUFFER_CONTENTS:
        init_aes_lut(emu, name, dir_path / blob_path, p_sb, p_sb_off, trace)

    plain = emu.malloc(BUFFER_SIZE)
    cypher = emu.malloc(BUFFER_SIZE)
    plain_sb = new_sb(emu, plain, trace, "plain")
    cypher_sb = new_sb(emu, cypher, trace, "cypher")
    
    emu.mem.write(plain, b"\0" * BUFFER_SIZE)
    emu.mem.write(cypher, b"\0" * BUFFER_SIZE)

    execution = ExecutionTrace(dir_path / "execution.txt") if args.execution_trace else None
    execution_hook = (
        None if execution is None else emu.uc.hook_add(UC_HOOK_CODE, execution.on_code)
    )
    random_run = args.random is not None
    run_count = args.random if random_run else 1
    fixed_plain = args.plain if args.plain is not None else bytes(BUFFER_SIZE)

    try:
        for run_index in range(run_count):
            plain_value = os.urandom(BUFFER_SIZE) if random_run else fixed_plain
            if trace is not None:
                trace.reset()
            emu.mem.write(plain, plain_value)
            emu.mem.write(cypher, b"\0" * BUFFER_SIZE)
            print_run_start(run_index, plain_value)
            try:
                if execution is None:
                    ret = call_reusing_stack(emu, AES_USER_DATA, plain_sb, 0, cypher_sb, 0, BUFFER_SIZE)
                else:
                    with execution:
                        ret = call_reusing_stack(emu, AES_USER_DATA, plain_sb, 0, cypher_sb, 0, BUFFER_SIZE)
            finally:
                if trace is not None:
                    trace.write()

            cypher_value = emu.mem.read(cypher, BUFFER_SIZE)
            print_result(ret, cypher_value)
    finally:
        if execution_hook is not None:
            emu.uc.hook_del(execution_hook)

if __name__ == "__main__":
    main()
