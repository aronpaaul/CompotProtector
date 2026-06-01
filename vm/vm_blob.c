typedef unsigned long long u64;
typedef long long i64;
typedef unsigned int u32;

static int condEval(unsigned char c, int zf, int sf, int of, int cf);
__attribute__((used)) static void vmRun(u64 *R, unsigned char *code, u32 masks);
void vmEnter(void);

#ifndef VM_TEST
__attribute__((naked, used)) void vmLoader(void) {
    asm volatile(
        ".intel_syntax noprefix\n"
        "push rax\n push rcx\n push rdx\n push rsi\n push r8\n push r9\n"
        "mov rax, [rsp+48]\n"
        "lea rcx, [rip+gFlag]\n"
        "cmp byte ptr [rcx], 0\n"
        "jne 2f\n"
        "mov byte ptr [rcx], 1\n"
        "mov ecx, [rax+16]\n"
        "mov edx, [rax+20]\n"
        "lea rsi, [rip+vmEnter]\n"
        "xor r8d, r8d\n"
        "1:\n"
        "cmp r8d, ecx\n"
        "jae 2f\n"
        "mov r9d, edx\n"
        "add r9d, r8d\n"
        "mov al, [rsi+r8]\n"
        "xor al, r9b\n"
        "mov [rsi+r8], al\n"
        "inc r8d\n"
        "jmp 1b\n"
        "2:\n"
        "pop r9\n pop r8\n pop rsi\n pop rdx\n pop rcx\n pop rax\n"
        "jmp vmEnter\n"
        "gFlag: .byte 0\n"
        ".att_syntax prefix\n");
}

__attribute__((naked, used)) void vmEnter(void) {
    asm volatile(
        ".intel_syntax noprefix\n"
        "push r15\n push r14\n push r13\n push r12\n push r11\n push r10\n push r9\n push r8\n"
        "push rdi\n push rsi\n push rbp\n push rsp\n push rbx\n push rdx\n push rcx\n push rax\n"
        "mov rbx, rsp\n"
        "mov r10, [rsp+128]\n"
        "mov rsi, [r10]\n"
        "mov ecx, [r10+8]\n"
        "mov edx, [r10+12]\n"
        "add qword ptr [rsp+128], 24\n"
        "sub rsp, 0x1010\n"
        "and rsp, -16\n"
        "mov rdi, rsp\n"
        "xor r8d, r8d\n"
        "1:\n"
        "cmp r8d, ecx\n"
        "jae 2f\n"
        "mov r9d, edx\n"
        "add r9d, r8d\n"
        "mov al, [rsi+r8]\n"
        "xor al, r9b\n"
        "mov [rdi+r8], al\n"
        "inc r8d\n"
        "jmp 1b\n"
        "2:\n"
        "mov rcx, rbx\n"
        "mov r8d, edx\n"
        "mov rdx, rdi\n"
        "sub rsp, 0x20\n"
        "and rsp, -16\n"
        "call vmRun\n"
        "lea rsp, [rbx]\n"
        "pop rax\n pop rcx\n pop rdx\n pop rbx\n add rsp, 8\n pop rbp\n pop rsi\n pop rdi\n"
        "pop r8\n pop r9\n pop r10\n pop r11\n pop r12\n pop r13\n pop r14\n pop r15\n"
        "ret\n"
        ".att_syntax prefix\n");
}
#endif

static int condEval(unsigned char c, int zf, int sf, int of, int cf) {
    switch (c) {
        case 2:  return cf;            case 3:  return !cf;
        case 4:  return zf;            case 5:  return !zf;
        case 6:  return cf || zf;      case 7:  return !cf && !zf;
        case 8:  return sf;            case 9:  return !sf;
        case 12: return sf != of;      case 13: return sf == of;
        case 14: return zf || (sf != of);
        case 15: return !zf && (sf == of);
        default: return 0;
    }
}

static inline u64 rd(u64 *R, u64 *S, unsigned i) { return i < 16 ? R[i] : S[i - 16]; }
static inline void wr(u64 *R, u64 *S, unsigned i, u64 v) { if (i < 16) R[i] = v; else S[i - 16] = v; }

static u32 keyAt(u32 base, u32 idx) {
    u32 x = base ^ (idx * 0x9E3779B1u);
    x ^= x >> 15;
    x *= 0x85EBCA77u;
    x ^= x >> 13;
    x *= 0xC2B2AE3Du;
    x ^= x >> 16;
    return x;
}

static void vmRun(u64 *R, unsigned char *code, u32 masks) {
    u32 pc = 0;
    u64 S[16] = {0};
    int zf = 0, sf = 0, of = 0, cf = 0;
    for (;;) {
        unsigned char *in = code + pc;
        unsigned char d[16];
        for (int q = 0; q < 4; q++) {
            u32 kk = keyAt(masks, (pc >> 4) * 4 + q);
            d[q * 4 + 0] = in[q * 4 + 0] ^ (unsigned char)kk;
            d[q * 4 + 1] = in[q * 4 + 1] ^ (unsigned char)(kk >> 8);
            d[q * 4 + 2] = in[q * 4 + 2] ^ (unsigned char)(kk >> 16);
            d[q * 4 + 3] = in[q * 4 + 3] ^ (unsigned char)(kk >> 24);
        }
        unsigned char op = d[0];
        if (op == 0x30) return;
        if (op == 0x20) { pc = *(u32 *)(d + 8); continue; }
        if (op == 0x21) {
            int take = condEval(d[1], zf, sf, of, cf);
            pc = take ? *(u32 *)(d + 8) : pc + 16;
            continue;
        }
        if (op == 0x41) {
            if (condEval(d[1], zf, sf, of, cf)) wr(R, S, d[3], rd(R, S, d[5]));
            pc += 16;
            continue;
        }
        if (op == 0x40) {
            unsigned char mode = d[1], msz = d[2], mreg = d[3], mb = d[4], mi = d[5], msc = d[6];
            i64 mdisp = *(i64 *)(d + 8);
            u64 addr = (u64)mdisp;
            if (mb != 0xFF) addr += rd(R, S, mb);
            if (mi != 0xFF) addr += rd(R, S, mi) * msc;
            if (mode == 2) { wr(R, S, mreg, msz == 4 ? (addr & 0xffffffffull) : addr); }
            else if (mode == 1) {
                u64 v = msz == 8 ? *(u64 *)addr : msz == 4 ? *(u32 *)addr : msz == 2 ? *(unsigned short *)addr : *(unsigned char *)addr;
                wr(R, S, mreg, v);
            } else if (mode == 3) {
                i64 v = msz == 4 ? *(int *)addr : msz == 2 ? *(short *)addr : *(signed char *)addr;
                wr(R, S, mreg, (u64)v);
            } else {
                if (msz == 8) *(u64 *)addr = rd(R, S, mreg);
                else if (msz == 4) *(u32 *)addr = (u32)rd(R, S, mreg);
                else if (msz == 2) *(unsigned short *)addr = (unsigned short)rd(R, S, mreg);
                else *(unsigned char *)addr = (unsigned char)rd(R, S, mreg);
            }
            pc += 16;
            continue;
        }
        unsigned char alu = d[1], size = d[2], dst = d[3], kind = d[4], src = d[5];
        i64 imm = *(i64 *)(d + 8);
        u64 mask = size == 8 ? ~0ull : 0xffffffffull;
        u64 sign = size == 8 ? 0x8000000000000000ull : 0x80000000ull;
        int bits = size == 8 ? 64 : 32;
        u64 a = rd(R, S, dst) & mask;
        u64 b = (kind ? (u64)imm : rd(R, S, src)) & mask;
        u64 res = a;
        int write = 1, setzs = 1, fadd = 0, fsub = 0;
        if (alu == 0) { res = b; setzs = 0; }
        else if (alu == 1) { res = a + b; fadd = 1; }
        else if (alu == 2) { res = a - b; fsub = 1; }
        else if (alu == 7) { res = a - b; fsub = 1; write = 0; }
        else if (alu == 3) { res = a ^ b; cf = 0; of = 0; }
        else if (alu == 4) { res = a & b; cf = 0; of = 0; }
        else if (alu == 5) { res = a | b; cf = 0; of = 0; }
        else if (alu == 11) { res = a & b; cf = 0; of = 0; write = 0; }
        else if (alu == 6) { res = a * b; setzs = 0; }
        else if (alu == 13) { res = ~a; setzs = 0; }
        else if (alu == 14) { res = a + 1; }
        else if (alu == 15) { res = a - 1; }
        else if (alu == 12) { u64 r2 = (0 - a) & mask; cf = (a != 0); of = ((a & r2 & sign) != 0); res = r2; }
        else if (alu == 8) { unsigned sh = b & (bits - 1); if (sh) cf = (a >> (bits - sh)) & 1; res = a << sh; of = 0; }
        else if (alu == 9) { unsigned sh = b & (bits - 1); if (sh) cf = (a >> (sh - 1)) & 1; res = (a & mask) >> sh; of = 0; }
        else if (alu == 10) { unsigned sh = b & (bits - 1); if (sh) cf = (a >> (sh - 1)) & 1; res = size == 8 ? (u64)(((i64)a) >> sh) : (u64)(u32)(((int)(u32)a) >> sh); of = 0; }
        else if (alu == 16) { unsigned sh = b & (bits - 1); res = sh ? ((a << sh) | ((a & mask) >> (bits - sh))) : a; setzs = 0; if (sh) cf = (res & 1); of = 0; }
        else if (alu == 17) { unsigned sh = b & (bits - 1); res = sh ? (((a & mask) >> sh) | (a << (bits - sh))) : a; setzs = 0; if (sh) cf = (res >> (bits - 1)) & 1; of = 0; }
        res &= mask;
        if (fadd) { cf = res < a; of = ((~(a ^ b) & (a ^ res)) & sign) != 0; }
        if (fsub) { cf = a < b; of = (((a ^ b) & (a ^ res)) & sign) != 0; }
        if (setzs) { zf = (res == 0); sf = (res & sign) != 0; }
        if (write) wr(R, S, dst, res);
        pc += 16;
    }
}
