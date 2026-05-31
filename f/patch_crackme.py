#!/usr/bin/env python3
"""
patch_crackme_v2.py — запускать на Windows
pip install pefile capstone
"""

import ctypes, struct, sys, os
import pefile, capstone

# ─── Crypto ─────────────────────────────────────────────────────────────────

M = 0xFFFFFFFFFFFFFFFF

def _r32(v, n): v &= 0xFFFFFFFF; n &= 31; return ((v<<n)|(v>>(32-n))) & 0xFFFFFFFF
def _r64(v, n): v &= M;         n &= 63;  return ((v<<n)|(v>>(64-n))) & M

_C0  = _r64(0xeae6dedacae0e6ca, 7);  _C1  = _r64(0xedac8dee4c2dcc8d, 11)
_C2  = _r64(0xae4c2d8f2cecadcc, 19); _C3  = _r64(0xe8cae6e8cac8c4f2, 23)
_C4  = _r64(0xe0acf1bbcdcbfa53, 13)
_MC4 = _r64(0xe0acf1bbcdcbfa53, 13); _MC5 = _r64(0x72dcdfac23b68e72, 17)
_MC6 = _r64(0xd899888f5ca6824d, 37)

def _qr(r8, r9, r10, rax):
    r8=(r8+r9)&M;  r9=_r64(r9,13)^r8;   r8=_r64(r8,32)
    r10=(r10+rax)&M; rax=_r64(rax,16)^r10
    r8=(r8+rax)&M;  rax=_r64(rax,21)^r8
    r10=(r10+r9)&M;  r9=_r64(r9,17)^r10; r10=_r64(r10,32)
    return r8,r9,r10,rax

def keygen(widx, key):
    r14=(key^_C4)&M; r8=(key^_C0)&M; r9=(r14^_C1)&M
    r10=(key^_C2)&M; rax=((r14^_C3)^widx)&M
    for _ in range(2): r8,r9,r10,rax=_qr(r8,r9,r10,rax)
    r8^=widx; rax^=_r64(0x40000000,29)
    for _ in range(2): r8,r9,r10,rax=_qr(r8,r9,r10,rax)
    r8^=_r64(0x10000000,31); r10^=0xFF
    for _ in range(4): r8,r9,r10,rax=_qr(r8,r9,r10,rax)
    r8=(r8^r9)&M; r8=(r8^r10)&M; rax=(rax^r8)&M
    return rax

def mba(rcx, rdx=0x53454c46):
    rax=rdx&0xFFFFFFFF; rax=(rax*_MC4)&M; rax^=rcx
    rax^=(rax>>30); rax&=M; rax=(rax*_MC5)&M
    rax^=(rax>>27); rax&=M; rax=(rax*_MC6)&M
    rax^=(rax>>31); rax&=M; rax|=1; return rax

def stream_xor(data, key, offset=0):
    out = bytearray(len(data))
    for i in range(len(data)):
        pos=(offset+i)&0xFFFFFFFF; ks=keygen(pos>>3,key)
        out[i]=data[i]^((ks>>((pos&7)*8))&0xFF)
    return bytes(out)

# ─── Windows helpers (правильный restype для x64) ───────────────────────────

_K32 = None
def _k32():
    global _K32
    if _K32 is None:
        _K32 = ctypes.windll.kernel32
        # Все функции, возвращающие указатели — c_size_t (не c_int!)
        _K32.GetModuleHandleW.restype  = ctypes.c_size_t
        _K32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
        _K32.GetCurrentProcess.restype = ctypes.c_size_t
        _K32.GetCurrentProcess.argtypes= []
        _K32.VirtualAlloc.restype  = ctypes.c_size_t
        _K32.VirtualAlloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t,
                                       ctypes.c_uint32, ctypes.c_uint32]
        _K32.VirtualFree.restype   = ctypes.c_bool
        _K32.VirtualFree.argtypes  = [ctypes.c_size_t, ctypes.c_size_t, ctypes.c_uint32]
        _K32.ReadProcessMemory.restype  = ctypes.c_bool
        _K32.ReadProcessMemory.argtypes = [ctypes.c_size_t, ctypes.c_size_t,
                                            ctypes.c_void_p, ctypes.c_size_t,
                                            ctypes.POINTER(ctypes.c_size_t)]
    return _K32


def read_mem(addr, n):
    k = _k32()
    buf  = (ctypes.c_uint8 * n)()
    read = ctypes.c_size_t(0)
    ok   = k.ReadProcessMemory(k.GetCurrentProcess(), addr, buf, n, ctypes.byref(read))
    if not ok or read.value < n:
        raise RuntimeError(f"ReadProcessMemory({hex(addr)}, {n}) failed")
    return bytes(buf)


# CPUID: leaf → (eax, ebx, ecx, edx)
# Шеллкод: rcx=leaf, rdx=subleaf, r8=out_buf[4 x uint32]
_CPUID_SC = bytes([
    0x53,                    # push rbx
    0x89, 0xC8,              # mov eax, ecx
    0x89, 0xD1,              # mov ecx, edx
    0x0F, 0xA2,              # cpuid
    0x41, 0x89, 0x00,        # mov [r8],    eax
    0x41, 0x89, 0x58, 0x04,  # mov [r8+4],  ebx
    0x41, 0x89, 0x48, 0x08,  # mov [r8+8],  ecx
    0x41, 0x89, 0x50, 0x0C,  # mov [r8+12], edx
    0x5B,                    # pop rbx
    0xC3,                    # ret
])

def cpuid(leaf, subleaf=0):
    k   = _k32()
    mem = k.VirtualAlloc(0, len(_CPUID_SC), 0x3000, 0x40)
    if not mem:
        raise RuntimeError("VirtualAlloc failed")
    ctypes.memmove(mem, _CPUID_SC, len(_CPUID_SC))
    buf = (ctypes.c_uint32 * 4)()
    FT  = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.c_uint32,
                            ctypes.POINTER(ctypes.c_uint32))
    FT(mem)(ctypes.c_uint32(leaf), ctypes.c_uint32(subleaf), buf)
    k.VirtualFree(mem, 0, 0x8000)
    return buf[0], buf[1], buf[2], buf[3]


def compute_env_key():
    k    = _k32()
    base = k.GetModuleHandleW("ntdll.dll")
    if not base:
        raise RuntimeError("GetModuleHandleW('ntdll.dll') returned 0")

    raw60 = read_mem(base, 60)

    h = 0
    for b in raw60:
        h = (_r32(h, 5) ^ b) & 0xFFFFFFFF

    eax, _, ecx, edx = cpuid(1)

    r9 = _r32((h ^ eax) & 0xFFFFFFFF, 7)
    r9 = _r32((r9 ^ ecx) & 0xFFFFFFFF, 7)
    r9 = (r9 ^ edx) & 0xFFFFFFFF
    return r9, h, eax, ecx, edx

# ─── PE constants ────────────────────────────────────────────────────────────

STRUCT_RVA      = 0x1a0e0
HJT_RVA         = 0x19000
EP_SIZE         = 0x0dd4
PAYLOAD_SRC_RVA = 0x1acd0
PAYLOAD_SIZE    = 0xf550
PAYLOAD_DST_RVA = 0x1000

_GOOD_MN = {'mov','lea','push','pop','add','sub','xor','and','or','cmp','test',
            'jmp','je','jne','jl','jg','jle','jge','call','ret','nop','inc','dec',
            'imul','movsxd','movzx','movsx','not','neg','shl','shr','sar','sal',
            'rol','ror','cdq','cdqe','movabs','xchg'}
_BAD_MN  = {'retf','into','out','in','hlt','rdmsr','wrmsr','iret','loopne','xlatb'}

def _score(ins, n=12):
    return sum(1 for i in ins[:n] if i.mnemonic in _GOOD_MN)

def _try(cipher, key, offset, label, base_va, quiet=False):
    md  = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    dec = stream_xor(cipher, key, offset)
    ins = list(md.disasm(dec[:80], base_va))
    if len(ins) < 8: return None
    if any(i.mnemonic in _BAD_MN for i in ins[:5]): return None
    sc = _score(ins)
    if sc >= 8:
        if not quiet:
            print(f"    HIT {label} (score={sc})")
            for i in ins[:4]: print(f"      {hex(i.address)}: {i.mnemonic} {i.op_str}")
        return dec
    return None

# ─── EP analysis ─────────────────────────────────────────────────────────────

def find_ep_decrypt_call(ep_dec, base):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    DECRYPT_VA = base + 0x19e46
    MBA_VA     = base + 0x19f8b
    instrs = list(md.disasm(ep_dec, base + HJT_RVA))
    for idx, ins in enumerate(instrs):
        if ins.mnemonic != 'call': continue
        try: tgt = int(ins.op_str, 16)
        except: continue
        if tgt != DECRYPT_VA: continue
        window = instrs[max(0, idx-30):idx]
        r9_val = 0
        for w in reversed(window):
            if 'xor' in w.mnemonic and 'r9d, r9d' in w.op_str: break
            if w.mnemonic == 'mov' and w.op_str.startswith('r9d,'):
                try: r9_val = int(w.op_str.split(',')[1].strip(), 16) & 0xFFFFFFFF
                except: pass
                break
        for widx, w in enumerate(window):
            if w.mnemonic == 'call':
                try: wtgt = int(w.op_str, 16)
                except: continue
                if wtgt != MBA_VA: continue
                pre = window[max(0, widx-15):widx]
                for p in reversed(pre):
                    if p.mnemonic in ('mov','movabs') and p.op_str.startswith('rcx,'):
                        try:
                            raw = int(p.op_str.split(',')[1].strip(), 16)
                            ck  = mba(raw)
                            print(f"    EP: mba_input={hex(raw)} → ck={hex(ck)} off={hex(r9_val)}")
                            return ck, r9_val
                        except: pass
    return None

# ─── Password check finder ───────────────────────────────────────────────────

def find_patches(payload, base_va):
    md     = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    instrs = list(md.disasm(payload, base_va))
    patches = []
    seen    = set()
    for idx in range(len(instrs) - 1):
        ins = instrs[idx]; nxt = instrs[idx+1]
        is_cmp = (ins.mnemonic in ('test','cmp') and
                  any(r in ins.op_str for r in ('eax, eax','rax, rax','eax, 0','rax, 0')))
        if not is_cmp: continue
        if nxt.mnemonic not in ('je','jne','jz','jnz'): continue
        off = ins.address - base_va
        if off in seen: continue
        seen.add(off)
        nb = nxt.bytes
        if   nxt.size == 2: br_p = (b'\xEB'+bytes([nb[1]]) if nb[0] in (0x74,0x78)
                                     else b'\x90\x90')
        elif nxt.size == 6: br_p = (b'\xE9'+nb[2:] if nb[1] in (0x84,0x88)
                                     else b'\x90'*6)
        else: continue
        patches.append({
            'va':   ins.address,
            'desc': f"{ins.mnemonic} {ins.op_str} + {nxt.mnemonic} @ {hex(nxt.address)}",
            't':    (off,               ins.bytes, b'\x90'*ins.size),
            'b':    (nxt.address-base_va, nb,       br_p),
        })
    return patches

# ─── Write patched binary ────────────────────────────────────────────────────

def write_patch(pe_path, pe, payload_dec, key, offset, patch_list):
    raw = bytearray(pe.__data__)
    p2  = bytearray(payload_dec)
    for p in patch_list:
        ot, _, nt = p['t']; ob, _, nb = p['b']
        p2[ot:ot+len(nt)] = nt
        p2[ob:ob+len(nb)] = nb
        print(f"  [patch] {p['desc']}")
    enc = stream_xor(bytes(p2), key, offset)
    fo  = pe.get_offset_from_rva(PAYLOAD_SRC_RVA)
    raw[fo:fo+len(enc)] = enc
    out = os.path.splitext(pe_path)[0] + '_patched.exe'
    with open(out, 'wb') as f: f.write(raw)
    return out

# ─── main ────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python patch_crackme_v2.py crackme-encrypted.exe"); sys.exit(1)

    pe_path = sys.argv[1]
    pe      = pefile.PE(pe_path)
    base    = pe.OPTIONAL_HEADER.ImageBase

    print("[1] env_key ...")
    env_key, ntdll_h, c_eax, c_ecx, c_edx = compute_env_key()
    print(f"    ntdll_hash = {hex(ntdll_h)}")
    print(f"    CPUID.EAX  = {hex(c_eax)}  ECX={hex(c_ecx)}  EDX={hex(c_edx)}")
    print(f"    env_key    = {hex(env_key)}")

    print("\n[2] Расшифровываю EP-стаб ...")
    raw_a8 = struct.unpack_from('<Q', pe.__data__, pe.get_offset_from_rva(STRUCT_RVA+0xa8))[0]
    ep_key = mba(((raw_a8>>32)<<32) | ((raw_a8&0xFFFFFFFF)^env_key))
    ep_enc = pe.__data__[pe.get_offset_from_rva(HJT_RVA): pe.get_offset_from_rva(HJT_RVA)+EP_SIZE]
    ep_dec = stream_xor(ep_enc, ep_key, 0)

    md   = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    ins0 = list(md.disasm(ep_dec[:64], base+HJT_RVA))
    ep_ok = _score(ins0) >= 7 and not any(i.mnemonic in _BAD_MN for i in ins0[:5])
    print(f"    ep_cipher_key = {hex(ep_key)}, ep_valid = {ep_ok}")
    if ins0:
        for i in ins0[:4]: print(f"      {hex(i.address)}: {i.mnemonic} {i.op_str}")

    with open('ep_dec.bin','wb') as f: f.write(ep_dec)
    print("    Сохранено ep_dec.bin")

    print("\n[3] Ключ пейлоада ...")
    pay_enc = pe.__data__[pe.get_offset_from_rva(PAYLOAD_SRC_RVA):
                           pe.get_offset_from_rva(PAYLOAD_SRC_RVA)+PAYLOAD_SIZE]
    key1    = struct.unpack_from('<Q', pe.__data__, pe.get_offset_from_rva(STRUCT_RVA+0x70))[0]
    k1e     = ((key1>>32)<<32) | ((key1&0xFFFFFFFF)^env_key)

    payload_dec = None; pkey = None; poff = 0

    if ep_ok:
        res = find_ep_decrypt_call(ep_dec, base)
        if res:
            ck, off = res
            d = _try(pay_enc, ck, off, "from EP", base+PAYLOAD_DST_RVA)
            if d: payload_dec, pkey, poff = d, ck, off

    if payload_dec is None:
        hyps = [
            (mba(k1e),  0,       "mba(key1^env)   off=0"),
            (mba(k1e),  0x1000,  "mba(key1^env)   off=0x1000"),
            (mba(k1e),  0x1acd0, "mba(key1^env)   off=0x1acd0"),
            (mba(key1), 0,       "mba(key1)       off=0"),
            (mba(key1), 0x1000,  "mba(key1)       off=0x1000"),
            (mba(key1), 0x1acd0, "mba(key1)       off=0x1acd0"),
            (key1,      0,       "key1 raw        off=0"),
            (key1,      0x1000,  "key1 raw        off=0x1000"),
            (ep_key,    0,       "ep_cipher_key   off=0"),
            (ep_key,    0x1000,  "ep_cipher_key   off=0x1000"),
        ]
        for ck, off, lbl in hyps:
            d = _try(pay_enc, ck, off, lbl, base+PAYLOAD_DST_RVA)
            if d: payload_dec, pkey, poff = d, ck, off; break

    if payload_dec is None:
        print("[!] Пейлоад не расшифровался — нужно смотреть ep_dec.bin в IDA/Ghidra")
        print("    Найди первый `call 0x140019e46` в EP и посмотри r8 перед ним.")
        sys.exit(1)

    print(f"\n[+] Пейлоад OK: {len(payload_dec)} bytes  key={hex(pkey)} off={hex(poff)}")
    with open('payload_dec.bin','wb') as f: f.write(payload_dec)
    print("    Сохранено payload_dec.bin")

    print("\n[4] Поиск проверки пароля ...")
    patches = find_patches(payload_dec, base+PAYLOAD_DST_RVA)
    if not patches:
        print("[!] Паттерн не найден автоматически.")
        print("    Открой payload_dec.bin и ищи test eax,eax + jne/je после строкового сравнения.")
        sys.exit(1)

    print(f"    {len(patches)} кандидат(ов):")
    for i, p in enumerate(patches): print(f"    [{i}] VA={hex(p['va'])} — {p['desc']}")

    print("\n[5] Записываю патч ...")
    out = write_patch(pe_path, pe, payload_dec, pkey, poff, patches)
    print(f"\n[+] Готово → {out}")

if __name__ == '__main__':
    main()