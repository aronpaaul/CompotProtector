.intel_syntax noprefix
.text

.equ P_FLAGS, 0
.equ P_SCOUNT, 4
.equ P_STAB, 8
.equ P_SINT, 12
.equ P_SWIN, 16
.equ P_IDLL, 20
.equ P_ITAB, 24
.equ P_ILEN, 28
.equ P_IKEY, 32
.equ P_IINT, 36
.equ P_IWIN, 40
.equ P_OEP, 44
.equ P_HLL, 48
.equ P_HGP, 52
.equ P_HSL, 56
.equ P_HCT, 60
.equ P_PLL, 64
.equ P_PGP, 72
.equ P_PSL, 80
.equ P_PCT, 88
.equ P_K32, 96
.equ P_OCB, 104
.equ P_OCBN, 108
.equ P_HCRDP, 112
.equ P_HEXIT, 116
.equ P_CRVA, 120
.equ P_CLEN, 124
.equ P_CKEY, 128
.equ P_CBLOB, 128
.equ P_SELFRVA, 132
.equ P_SELFLEN, 136
.equ P_SELFKEY, 140
.equ P_HVP, 144
.equ P_PVP, 148
.equ P_BMAP, 156
.equ P_PAGES, 160
.equ P_LAZYINT, 164
.equ P_SEED, 168
.equ P_SBACKUP, 32
.equ P_ICHECK, 140
.equ P_HQIP, 176
.equ P_HSIT, 180
.equ P_HNTC, 184
.equ P_TAMPER, 188
.equ P_TCHECK, 192
.equ FLAG_LAZY, 16
.equ FLAG_ZERO_STRINGS, 32
.equ TAG_SELF, 0x53454C46
.equ TAG_CODE, 0x434F4445
.equ TAG_IMPORT, 0x494D5054
.equ TAG_STRING, 0x53545247

.globl _start
_start:
    mov   r15, rsp
    and   rsp, -16
    sub   rsp, 0x60
    lea   rdi, [rip+params]
    mov   rax, gs:[0x60]
    mov   rbx, [rax+0x10]
    call  findKernel32
    mov   [rdi+P_K32], rax
    test  rax, rax
    jz    stOep
    mov   r12, rax
    mov   rcx, r12
    mov   edx, [rdi+P_HLL]
    call  findExportByHash
    mov   [rdi+P_PLL], rax
    mov   rcx, r12
    mov   edx, [rdi+P_HGP]
    call  findExportByHash
    mov   [rdi+P_PGP], rax
    mov   rcx, r12
    mov   edx, [rdi+P_HSL]
    call  findExportByHash
    mov   [rdi+P_PSL], rax
    mov   rcx, r12
    mov   edx, [rdi+P_HCT]
    call  findExportByHash
    mov   [rdi+P_PCT], rax
    lea   rcx, [rip+user32Name]
    mov   rax, [rdi+P_PLL]
    call  rax
    mov   eax, [rdi+P_FLAGS]
    test  eax, 8
    jz    stNoAd
    call  antiDebug
stNoAd:
    mov   eax, [rdi+P_FLAGS]
    test  eax, 64
    jz    stNoVm
    call  antiVm
stNoVm:
    call  integrityCheck
    cmp   eax, [rdi+P_ICHECK]
    je    stIntOk
    lea   rdx, [rip+tamperMsg]
    call  showTamper
stIntOk:
    call  applyStrings
    call  applyCode
    mov   eax, [rdi+P_FLAGS]
    test  eax, 2
    jz    stNoImp
    call  resolveImports
stNoImp:
    mov   eax, [rdi+P_OCBN]
    test  eax, eax
    jz    stNoOcb
    call  callOriginals
stNoOcb:
    mov   eax, [rdi+P_FLAGS]
    test  eax, 1
    jz    stNoStr
    lea   r8, [rip+stringThread]
    call  startThread
stNoStr:
    mov   eax, [rdi+P_FLAGS]
    test  eax, 4
    jz    stNoImpThr
    lea   r8, [rip+importThread]
    call  startThread
stNoImpThr:
    mov   eax, [rdi+P_FLAGS]
    test  eax, FLAG_LAZY
    jz    stNoLazy
    lea   r8, [rip+lazyThread]
    call  startThread
stNoLazy:
    mov   eax, [rdi+P_FLAGS]
    test  eax, FLAG_ZERO_STRINGS
    jz    stNoZero
    lea   r8, [rip+zeroThread]
    call  startThread
stNoZero:
    mov   eax, [rdi+P_FLAGS]
    test  eax, 8
    jz    stNoWatch
    lea   r8, [rip+watchThread]
    call  startThread
    lea   r8, [rip+integrityThread]
    call  startThread
stNoWatch:
stOep:
    mov   ecx, [rdi+P_OEP]
    mov   eax, ecx
    lea   rax, [rbx+rax]
    mov   rsp, r15
    jmp   rax

startThread:
    push  rbp
    mov   rbp, rsp
    sub   rsp, 0x30
    mov   rax, [rdi+P_PCT]
    test  rax, rax
    jz    sttDone
    xor   ecx, ecx
    xor   edx, edx
    xor   r9d, r9d
    mov   qword ptr [rsp+0x20], 0
    mov   qword ptr [rsp+0x28], 0
    call  rax
sttDone:
    mov   rsp, rbp
    pop   rbp
    ret

antiDebug:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  r12
    and   rsp, -16
    sub   rsp, 0x40
    lea   rdi, [rip+params]
    mov   rax, gs:[0x60]
    movzx ecx, byte ptr [rax+0x02]
    mov   edx, [rax+0xBC]
    and   edx, 0x70
    lea   ecx, [rdx+rcx*8]
    test  ecx, ecx
    jnz   adKill
    call  hookScan
    test  eax, eax
    jnz   adKill
    mov   r12, [rdi+P_K32]
    mov   rcx, r12
    mov   edx, [rdi+P_HCRDP]
    call  findExportByHash
    test  rax, rax
    jz    adDone
    mov   dword ptr [rsp+0x30], 0
    mov   rcx, -1
    lea   rdx, [rsp+0x30]
    call  rax
    mov   eax, [rsp+0x30]
    test  eax, eax
    jnz   adKill
adDone:
    lea   rsp, [rbp-16]
    pop   r12
    pop   rbx
    pop   rbp
    ret
adKill:
    mov   rcx, [rdi+P_K32]
    mov   edx, [rdi+P_HEXIT]
    call  findExportByHash
    test  rax, rax
    jz    adHard
    xor   ecx, ecx
    call  rax
adHard:
    ud2

antiVm:
    push  rbx
    mov   eax, 1
    cpuid
    bt    ecx, 31
    pop   rbx
    jc    adKill
    ret

callOriginals:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  rsi
    push  r12
    push  r13
    and   rsp, -16
    sub   rsp, 0x30
    lea   rdi, [rip+params]
    mov   rax, gs:[0x60]
    mov   r13, [rax+0x10]
    mov   eax, [rdi+P_OCB]
    lea   rsi, [r13+rax]
    mov   r12d, [rdi+P_OCBN]
coLoop:
    test  r12d, r12d
    jz    coDone
    mov   rax, [rsi]
    mov   rcx, r13
    mov   edx, 1
    mov   r8d, 1
    call  rax
    add   rsi, 8
    dec   r12d
    jmp   coLoop
coDone:
    lea   rsp, [rbp-32]
    pop   r13
    pop   r12
    pop   rsi
    pop   rbx
    pop   rbp
    ret

applyCode:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  rsi
    push  rdi
    push  r12
    and   rsp, -16
    sub   rsp, 0x40
    lea   rdi, [rip+params]
    mov   ecx, [rdi+P_CLEN]
    test  ecx, ecx
    jz    acRet
    mov   rax, gs:[0x60]
    mov   rbx, [rax+0x10]
    mov   edx, [rdi+P_CRVA]
    lea   rsi, [rbx+rdx]
    call  findKernel32
    test  rax, rax
    jz    acRet
    mov   r12, rax
    mov   rcx, r12
    mov   edx, [rdi+P_HVP]
    call  findExportByHash
    test  rax, rax
    jz    acRet
    mov   [rdi+P_PVP], rax
    mov   r10d, [rdi+P_CBLOB]
    lea   r10, [rbx+r10]
    mov   r11d, [rdi+P_CLEN]
    xor   r8d, r8d
acCopy:
    cmp   r8d, r11d
    jae   acCopyDone
    movzx eax, byte ptr [r10+r8]
    mov   byte ptr [rsi+r8], al
    inc   r8d
    jmp   acCopy
acCopyDone:
    mov   eax, [rdi+P_FLAGS]
    test  eax, FLAG_LAZY
    jnz   acLazy
    mov   rcx, [rdi+P_SEED]
    mov   edx, TAG_CODE
    call  deriveKey
    mov   r8, rax
    mov   rcx, rsi
    mov   edx, [rdi+P_CLEN]
    xor   r9d, r9d
    call  crypt
acProt:
    mov   rcx, rsi
    mov   edx, [rdi+P_CLEN]
    mov   r8d, 0x40
    lea   r9, [rsp+0x30]
    mov   rax, [rdi+P_PVP]
    call  rax
    jmp   acRet
acLazy:
    mov   rcx, r12
    mov   edx, [rdi+P_HGP]
    call  findExportByHash
    test  rax, rax
    jz    acRet
    mov   rcx, r12
    lea   rdx, [rip+avehName]
    call  rax
    test  rax, rax
    jz    acRet
    mov   ecx, 1
    lea   rdx, [rip+lazyHandler]
    call  rax
acRet:
    lea   rsp, [rbp-32]
    pop   r12
    pop   rdi
    pop   rsi
    pop   rbx
    pop   rbp
    ret

lazyHandler:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  rsi
    push  rdi
    push  r12
    push  r13
    push  r14
    and   rsp, -16
    sub   rsp, 0x40
    mov   rax, [rcx]
    cmp   dword ptr [rax], 0xC0000005
    jne   lhSearch
    mov   rsi, [rax+0x28]
    lea   rdi, [rip+params]
    mov   rax, gs:[0x60]
    mov   rbx, [rax+0x10]
    mov   eax, [rdi+P_CRVA]
    lea   r12, [rbx+rax]
    mov   r14d, [rdi+P_CLEN]
    cmp   rsi, r12
    jb    lhSearch
    lea   rax, [r12+r14]
    cmp   rsi, rax
    jae   lhSearch
    mov   r13, rsi
    sub   r13, r12
    and   r13, -4096
    mov   rcx, r13
    shr   rcx, 12
    mov   eax, [rdi+P_BMAP]
    lea   rdx, [rbx+rax]
    mov   rax, rcx
    shr   rax, 3
    lea   rsi, [rdx+rax]
    and   ecx, 7
    mov   r9d, 1
    shl   r9d, cl
    movzx eax, byte ptr [rsi]
    test  eax, r9d
    jz    lhSearch
    not   r9d
    and   byte ptr [rsi], r9b
    lea   r12, [r12+r13]
    mov   eax, r14d
    sub   eax, r13d
    cmp   eax, 0x1000
    jbe   lhLenOk
    mov   eax, 0x1000
lhLenOk:
    mov   r14d, eax
    mov   rcx, [rdi+P_SEED]
    mov   edx, TAG_CODE
    call  deriveKey
    mov   r8, rax
    mov   rcx, r12
    mov   edx, r14d
    mov   r9d, r13d
    call  crypt
lhProt:
    mov   rcx, r12
    mov   edx, 0x1000
    mov   r8d, 0x40
    lea   r9, [rsp+0x30]
    mov   rax, [rdi+P_PVP]
    call  rax
    mov   eax, -1
    jmp   lhRet
lhSearch:
    xor   eax, eax
lhRet:
    lea   rsp, [rbp-48]
    pop   r14
    pop   r13
    pop   r12
    pop   rdi
    pop   rsi
    pop   rbx
    pop   rbp
    ret

lazyThread:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  rsi
    push  rdi
    push  r12
    push  r13
    push  r14
    push  r15
    and   rsp, -16
    sub   rsp, 0x40
    lea   rdi, [rip+params]
ltLoop:
    mov   ecx, [rdi+P_LAZYINT]
    mov   rax, [rdi+P_PSL]
    call  rax
    mov   rax, gs:[0x60]
    mov   rbx, [rax+0x10]
    mov   eax, [rdi+P_CRVA]
    lea   r12, [rbx+rax]
    mov   r14d, [rdi+P_CLEN]
    mov   eax, [rdi+P_BMAP]
    lea   r15, [rbx+rax]
    mov   r13d, [rdi+P_PAGES]
    xor   esi, esi
ltPage:
    cmp   esi, r13d
    jae   ltLoop
    mov   eax, esi
    shr   eax, 3
    lea   r10, [r15+rax]
    mov   ecx, esi
    and   ecx, 7
    mov   r8d, 1
    shl   r8d, cl
    movzx eax, byte ptr [r10]
    test  eax, r8d
    jnz   ltNext
    mov   eax, esi
    shl   eax, 12
    lea   rcx, [r12+rax]
    mov   edx, 0x1000
    mov   r8d, 0x04
    lea   r9, [rsp+0x30]
    mov   rax, [rdi+P_PVP]
    call  rax
    mov   rcx, [rdi+P_SEED]
    mov   edx, TAG_CODE
    call  deriveKey
    mov   r10, rax
    mov   eax, esi
    shl   eax, 12
    mov   r11d, eax
    lea   rcx, [r12+rax]
    mov   r8d, r14d
    sub   r8d, r11d
    cmp   r8d, 0x1000
    jbe   ltLenOk
    mov   r8d, 0x1000
ltLenOk:
    mov   edx, r8d
    mov   r8, r10
    mov   r9d, r11d
    call  crypt
ltSetBit:
    mov   eax, esi
    shr   eax, 3
    lea   r11, [r15+rax]
    mov   ecx, esi
    and   ecx, 7
    mov   eax, 1
    shl   eax, cl
    or    byte ptr [r11], al
ltNext:
    inc   esi
    jmp   ltPage

applyStrings:
    push  rbx
    push  rsi
    push  rdi
    push  r12
    push  r13
    sub   rsp, 0x20
    lea   rdi, [rip+params]
    mov   r13d, [rdi+P_SCOUNT]
    test  r13d, r13d
    jz    asDone
    mov   rax, gs:[0x60]
    mov   r12, [rax+0x10]
    mov   eax, [rdi+P_STAB]
    lea   rsi, [r12+rax]
    xor   ebx, ebx
asStr:
    cmp   ebx, r13d
    jae   asDone
    mov   rcx, [rdi+P_SEED]
    mov   edx, TAG_STRING
    xor   edx, ebx
    call  deriveKey
    mov   r8, rax
    mov   eax, [rsi]
    lea   rcx, [r12+rax]
    mov   edx, [rsi+4]
    xor   r9d, r9d
    call  crypt
    add   rsi, 8
    inc   ebx
    jmp   asStr
asDone:
    add   rsp, 0x20
    pop   r13
    pop   r12
    pop   rdi
    pop   rsi
    pop   rbx
    ret

zeroStrings:
    push  rbx
    push  rsi
    push  rdi
    push  r12
    push  r13
    lea   rdi, [rip+params]
    mov   r13d, [rdi+P_SCOUNT]
    test  r13d, r13d
    jz    zsDone
    mov   rax, gs:[0x60]
    mov   r12, [rax+0x10]
    mov   eax, [rdi+P_STAB]
    lea   rsi, [r12+rax]
    xor   ebx, ebx
zsStr:
    cmp   ebx, r13d
    jae   zsDone
    mov   eax, [rsi]
    lea   rcx, [r12+rax]
    mov   edx, [rsi+4]
    xor   r8d, r8d
zsByte:
    cmp   r8d, edx
    jae   zsNext
    mov   byte ptr [rcx+r8], 0
    inc   r8d
    jmp   zsByte
zsNext:
    add   rsi, 8
    inc   ebx
    jmp   zsStr
zsDone:
    pop   r13
    pop   r12
    pop   rdi
    pop   rsi
    pop   rbx
    ret

showStrings:
    push  rbx
    push  rsi
    push  rdi
    push  r12
    push  r13
    push  r14
    push  r15
    sub   rsp, 0x20
    lea   rdi, [rip+params]
    mov   r13d, [rdi+P_SCOUNT]
    test  r13d, r13d
    jz    ssDone
    mov   rax, gs:[0x60]
    mov   r12, [rax+0x10]
    mov   eax, [rdi+P_STAB]
    lea   rsi, [r12+rax]
    mov   eax, [rdi+P_SBACKUP]
    lea   r14, [r12+rax]
    xor   ebx, ebx
ssStr:
    cmp   ebx, r13d
    jae   ssDone
    mov   eax, [rsi]
    lea   rcx, [r12+rax]
    mov   r15d, [rsi+4]
    xor   r8d, r8d
ssCopy:
    cmp   r8d, r15d
    jae   ssCopyDone
    movzx eax, byte ptr [r14+r8]
    mov   [rcx+r8], al
    inc   r8d
    jmp   ssCopy
ssCopyDone:
    mov   eax, r15d
    add   r14, rax
    mov   rcx, [rdi+P_SEED]
    mov   edx, TAG_STRING
    xor   edx, ebx
    call  deriveKey
    mov   r8, rax
    mov   eax, [rsi]
    lea   rcx, [r12+rax]
    mov   edx, r15d
    xor   r9d, r9d
    call  crypt
    add   rsi, 8
    inc   ebx
    jmp   ssStr
ssDone:
    add   rsp, 0x20
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    pop   rdi
    pop   rsi
    pop   rbx
    ret

zeroThread:
    push  rbp
    mov   rbp, rsp
    and   rsp, -16
    sub   rsp, 0x30
    lea   rdi, [rip+params]
    mov   ecx, [rdi+P_SINT]
    mov   rax, [rdi+P_PSL]
    call  rax
ztLoop:
    mov   al, byte ptr [rdi+P_TAMPER]
    test  al, al
    jnz   ztIdle
    call  zeroStrings
    mov   ecx, [rdi+P_SINT]
    mov   rax, [rdi+P_PSL]
    call  rax
    call  showStrings
    mov   ecx, [rdi+P_SWIN]
    mov   rax, [rdi+P_PSL]
    call  rax
    jmp   ztLoop
ztIdle:
    mov   ecx, [rdi+P_SINT]
    mov   rax, [rdi+P_PSL]
    call  rax
    jmp   ztLoop

ror13:
    xor   eax, eax
rorNext:
    movzx edx, byte ptr [rcx]
    ror   eax, 13
    add   eax, edx
    inc   rcx
    test  dl, dl
    jnz   rorNext
    ret

skipStr:
ssNext:
    cmp   byte ptr [rsi], 0
    je    ssEnd
    inc   rsi
    jmp   ssNext
ssEnd:
    inc   rsi
    ret

cmpUtf16Ascii:
cuNext:
    movzx eax, byte ptr [rdx]
    test  al, al
    jz    cuEq
    cmp   al, 0x41
    jb    cuFoldA
    cmp   al, 0x5A
    ja    cuFoldA
    add   al, 0x20
cuFoldA:
    movzx r8d, word ptr [rcx]
    cmp   r8d, 0x7F
    ja    cuNe
    mov   r9b, r8b
    cmp   r9b, 0x41
    jb    cuFoldB
    cmp   r9b, 0x5A
    ja    cuFoldB
    add   r9b, 0x20
cuFoldB:
    cmp   al, r9b
    jne   cuNe
    add   rcx, 2
    inc   rdx
    jmp   cuNext
cuEq:
    mov   eax, 1
    ret
cuNe:
    xor   eax, eax
    ret

findKernel32:
    push  rbx
    push  rsi
    push  rdi
    mov   rax, gs:[0x60]
    mov   rax, [rax+0x18]
    lea   rsi, [rax+0x10]
    mov   rdi, [rsi]
fkLoop:
    cmp   rdi, rsi
    je    fkFail
    movzx eax, word ptr [rdi+0x58]
    cmp   eax, 24
    jne   fkNext
    mov   rcx, [rdi+0x60]
    lea   rdx, [rip+kernel32Name]
    call  cmpUtf16Ascii
    test  eax, eax
    jnz   fkFound
fkNext:
    mov   rdi, [rdi]
    jmp   fkLoop
fkFound:
    mov   rax, [rdi+0x30]
    jmp   fkRet
fkFail:
    xor   eax, eax
fkRet:
    pop   rdi
    pop   rsi
    pop   rbx
    ret

findExportByHash:
    push  rbx
    push  rsi
    push  rdi
    push  r12
    push  r13
    push  r14
    push  r15
    mov   r12, rcx
    mov   r13d, edx
    mov   eax, [r12+0x3C]
    mov   eax, [r12+rax+0x88]
    test  eax, eax
    jz    feFail
    lea   r14, [r12+rax]
    mov   r15d, [r14+0x18]
    mov   eax, [r14+0x20]
    lea   rsi, [r12+rax]
    mov   eax, [r14+0x24]
    lea   rdi, [r12+rax]
    xor   ebx, ebx
feLoop:
    cmp   ebx, r15d
    jae   feFail
    mov   eax, [rsi+rbx*4]
    lea   rcx, [r12+rax]
    call  ror13
    cmp   eax, r13d
    je    feFound
    inc   ebx
    jmp   feLoop
feFound:
    movzx eax, word ptr [rdi+rbx*2]
    mov   ecx, [r14+0x1C]
    lea   rcx, [r12+rcx]
    mov   eax, [rcx+rax*4]
    lea   rax, [r12+rax]
    jmp   feRet
feFail:
    xor   eax, eax
feRet:
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    pop   rdi
    pop   rsi
    pop   rbx
    ret

resolveImports:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  rsi
    push  rdi
    push  r12
    push  r13
    push  r14
    push  r15
    and   rsp, -16
    sub   rsp, 0x40
    lea   rdi, [rip+params]
    mov   rax, gs:[0x60]
    mov   r15, [rax+0x10]
    mov   eax, [rdi+P_ITAB]
    lea   r14, [r15+rax]
    mov   rcx, [rdi+P_SEED]
    mov   edx, TAG_IMPORT
    call  deriveKey
    mov   r8, rax
    mov   rcx, r14
    mov   edx, [rdi+P_ILEN]
    xor   r9d, r9d
    call  crypt
    mov   r13d, [rdi+P_IDLL]
    mov   rsi, r14
riDll:
    test  r13d, r13d
    jz    riDone
    mov   rcx, rsi
    mov   rax, [rdi+P_PLL]
    call  rax
    mov   r12, rax
    call  skipStr
    mov   ebx, [rsi]
    add   rsi, 4
riFunc:
    test  ebx, ebx
    jz    riFuncEnd
    movzx eax, byte ptr [rsi]
    inc   rsi
    test  al, al
    jnz   riOrd
    mov   rcx, r12
    mov   rdx, rsi
    mov   rax, [rdi+P_PGP]
    call  rax
    call  skipStr
    jmp   riWrite
riOrd:
    movzx edx, word ptr [rsi]
    add   rsi, 2
    mov   rcx, r12
    mov   rax, [rdi+P_PGP]
    call  rax
riWrite:
    mov   ecx, [rsi]
    add   rsi, 4
    mov   [r15+rcx], rax
    dec   ebx
    jmp   riFunc
riFuncEnd:
    dec   r13d
    jmp   riDll
riDone:
    lea   rsp, [rbp-56]
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    pop   rdi
    pop   rsi
    pop   rbx
    pop   rbp
    ret

stringThread:
    push  rbp
    mov   rbp, rsp
    and   rsp, -16
    sub   rsp, 0x30
    lea   rdi, [rip+params]
tsLoop:
    mov   al, byte ptr [rdi+P_TAMPER]
    test  al, al
    jnz   tsIdle
    mov   ecx, [rdi+P_SINT]
    mov   rax, [rdi+P_PSL]
    call  rax
    call  applyStrings
    mov   ecx, [rdi+P_SWIN]
    mov   rax, [rdi+P_PSL]
    call  rax
    call  applyStrings
    jmp   tsLoop
tsIdle:
    mov   ecx, [rdi+P_SINT]
    mov   rax, [rdi+P_PSL]
    call  rax
    jmp   tsLoop

importThread:
    push  rbp
    mov   rbp, rsp
    and   rsp, -16
    sub   rsp, 0x30
    lea   rdi, [rip+params]
tiLoop:
    mov   ecx, [rdi+P_IINT]
    mov   rax, [rdi+P_PSL]
    call  rax
    call  xorIat
    mov   ecx, [rdi+P_IWIN]
    mov   rax, [rdi+P_PSL]
    call  rax
    call  xorIat
    jmp   tiLoop

xorIat:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  rsi
    push  rdi
    push  r13
    push  r15
    and   rsp, -16
    sub   rsp, 0x20
    lea   rdi, [rip+params]
    mov   rax, gs:[0x60]
    mov   r15, [rax+0x10]
    mov   eax, [rdi+P_ITAB]
    lea   rsi, [r15+rax]
    mov   r13d, [rdi+P_IDLL]
    mov   rcx, [rdi+P_SEED]
    mov   edx, TAG_IMPORT
    call  deriveKey
    mov   r8, rax
xiDll:
    test  r13d, r13d
    jz    xiDone
    call  skipStr
    mov   ebx, [rsi]
    add   rsi, 4
xiFunc:
    test  ebx, ebx
    jz    xiFuncEnd
    movzx eax, byte ptr [rsi]
    inc   rsi
    test  al, al
    jnz   xiOrd
    call  skipStr
    jmp   xiSlot
xiOrd:
    add   rsi, 2
xiSlot:
    mov   ecx, [rsi]
    add   rsi, 4
    mov   rax, [r15+rcx]
    mov   r9, r8
    shl   r9, 32
    or    r9, r8
    xor   rax, r9
    mov   [r15+rcx], rax
    dec   ebx
    jmp   xiFunc
xiFuncEnd:
    dec   r13d
    jmp   xiDll
xiDone:
    lea   rsp, [rbp-40]
    pop   r15
    pop   r13
    pop   rdi
    pop   rsi
    pop   rbx
    pop   rbp
    ret

findNtdll:
    push  rbx
    push  rsi
    push  rdi
    mov   rax, gs:[0x60]
    mov   rax, [rax+0x18]
    lea   rsi, [rax+0x10]
    mov   rdi, [rsi]
fnLoop:
    cmp   rdi, rsi
    je    fnFail
    movzx eax, word ptr [rdi+0x58]
    cmp   eax, 18
    jne   fnNext
    mov   rcx, [rdi+0x60]
    lea   rdx, [rip+ntdllName]
    call  cmpUtf16Ascii
    test  eax, eax
    jnz   fnFound
fnNext:
    mov   rdi, [rdi]
    jmp   fnLoop
fnFound:
    mov   rax, [rdi+0x30]
    jmp   fnRet
fnFail:
    xor   eax, eax
fnRet:
    pop   rdi
    pop   rsi
    pop   rbx
    ret

isHooked:
    test  rcx, rcx
    jz    ihNo
    movzx eax, byte ptr [rcx]
    cmp   al, 0xF3
    jne   ihChk
    movzx eax, byte ptr [rcx+4]
ihChk:
    cmp   al, 0xE9
    je    ihYes
    cmp   al, 0xFF
    je    ihYes
    cmp   al, 0xEB
    je    ihYes
    cmp   al, 0x68
    je    ihYes
    cmp   al, 0xE8
    je    ihYes
ihNo:
    xor   eax, eax
    ret
ihYes:
    mov   eax, 1
    ret

hookScan:
    push  rbx
    push  rsi
    push  rdi
    push  r12
    lea   rdi, [rip+params]
    call  findNtdll
    test  rax, rax
    jz    hsNo
    mov   r12, rax
    mov   rcx, r12
    mov   edx, [rdi+P_HQIP]
    call  findExportByHash
    mov   rcx, rax
    call  isHooked
    test  eax, eax
    jnz   hsYes
    mov   rcx, r12
    mov   edx, [rdi+P_HSIT]
    call  findExportByHash
    mov   rcx, rax
    call  isHooked
    test  eax, eax
    jnz   hsYes
    mov   rcx, r12
    mov   edx, [rdi+P_HNTC]
    call  findExportByHash
    mov   rcx, rax
    call  isHooked
    test  eax, eax
    jnz   hsYes
hsNo:
    xor   eax, eax
    jmp   hsRet
hsYes:
    mov   eax, 1
hsRet:
    pop   r12
    pop   rdi
    pop   rsi
    pop   rbx
    ret

watchThread:
    push  rbp
    mov   rbp, rsp
    and   rsp, -16
    sub   rsp, 0x30
    lea   rdi, [rip+params]
wtLoop:
    mov   ecx, 700
    mov   rax, [rdi+P_PSL]
    test  rax, rax
    jz    wtScan
    call  rax
wtScan:
    mov   rax, gs:[0x60]
    movzx ecx, byte ptr [rax+0x02]
    mov   edx, [rax+0xBC]
    and   edx, 0x70
    or    ecx, edx
    jnz   wtHit
    call  hookScan
    test  eax, eax
    jnz   wtHit
    jmp   wtLoop
wtHit:
    mov   al, byte ptr [rdi+P_TAMPER]
    test  al, al
    jnz   wtLoop
    mov   byte ptr [rdi+P_TAMPER], 1
    call  zeroStrings
    jmp   wtLoop

checksum:
    mov   eax, r8d
csLoop:
    test  edx, edx
    jz    csDone
    movzx r9d, byte ptr [rcx]
    xor   eax, r9d
    imul  eax, eax, 0x01000193
    inc   rcx
    dec   edx
    jmp   csLoop
csDone:
    ret

integrityCheck:
    push  rsi
    mov   rax, gs:[0x60]
    mov   rsi, [rax+0x10]
    mov   eax, [rdi+P_SELFRVA]
    lea   rcx, [rsi+rax]
    mov   edx, [rdi+P_SELFLEN]
    mov   r8d, 0x811C9DC5
    call  checksum
    mov   edx, [rdi+P_CLEN]
    test  edx, edx
    jz    icDone
    mov   r8d, eax
    mov   eax, [rdi+P_CBLOB]
    lea   rcx, [rsi+rax]
    mov   edx, [rdi+P_CLEN]
    call  checksum
icDone:
    pop   rsi
    ret

checkText:
    push  rsi
    mov   rax, gs:[0x60]
    mov   rsi, [rax+0x10]
    mov   eax, [rdi+P_CRVA]
    lea   rcx, [rsi+rax]
    mov   edx, [rdi+P_CLEN]
    mov   r8d, 0x811C9DC5
    call  checksum
    pop   rsi
    ret

showTamper:
    push  rbp
    mov   rbp, rsp
    push  rsi
    and   rsp, -16
    sub   rsp, 0x30
    mov   rsi, rdx
    lea   rcx, [rip+user32Name]
    mov   rax, [rdi+P_PLL]
    test  rax, rax
    jz    stKill
    call  rax
    test  rax, rax
    jz    stKill
    mov   rcx, rax
    lea   rdx, [rip+msgBoxName]
    mov   rax, [rdi+P_PGP]
    test  rax, rax
    jz    stKill
    call  rax
    test  rax, rax
    jz    stKill
    xor   ecx, ecx
    mov   rdx, rsi
    lea   r8, [rip+captionName]
    mov   r9d, 0x10
    call  rax
stKill:
    mov   rcx, [rdi+P_K32]
    mov   edx, [rdi+P_HEXIT]
    call  findExportByHash
    test  rax, rax
    jz    stHard
    mov   ecx, 0xDEAD
    call  rax
stHard:
    ud2

integrityThread:
    push  rbp
    mov   rbp, rsp
    and   rsp, -16
    sub   rsp, 0x30
    lea   rdi, [rip+params]
itLoop:
    mov   ecx, 100
    mov   rax, [rdi+P_PSL]
    call  rax
    call  integrityCheck
    cmp   eax, [rdi+P_ICHECK]
    jne   itTamper
    mov   eax, [rdi+P_FLAGS]
    test  eax, FLAG_LAZY
    jnz   itLoop
    mov   eax, [rdi+P_CLEN]
    test  eax, eax
    jz    itLoop
    call  checkText
    cmp   eax, [rdi+P_TCHECK]
    jne   itTamper
    jmp   itLoop
itTamper:
    lea   rdx, [rip+runtimeMsg]
    call  showTamper

user32Name:
    .asciz "user32.dll"
msgBoxName:
    .asciz "MessageBoxA"
captionName:
    .asciz "Error"
tamperMsg:
    .asciz "This application has been tampered with and cannot continue."
runtimeMsg:
    .asciz "Runtime integrity check failed. The application will now exit."
kernel32Name:
    .asciz "kernel32.dll"
ntdllName:
    .asciz "ntdll.dll"
avehName:
    .asciz "AddVectoredExceptionHandler"
.globl encEnd
encEnd:

tlsCallback:
    cmp   edx, 1
    jne   tcRet
    mov   eax, 0xB16B00B5
    imul  eax, eax, 0xCAFED00D
    xor   eax, 0x5EED1234
    push  rbx
    push  rsi
    push  rdi
    sub   rsp, 0x20
    lea   rdi, [rip+params]
    call  envHash
    xor   [rdi+P_SEED], eax
    mov   rax, gs:[0x60]
    mov   rbx, [rax+0x10]
    mov   esi, [rdi+P_SELFRVA]
    lea   rsi, [rbx+rsi]
    mov   rcx, [rdi+P_SEED]
    mov   edx, TAG_SELF
    call  deriveKey
    mov   r8, rax
    mov   rcx, rsi
    mov   edx, [rdi+P_SELFLEN]
    xor   r9d, r9d
    call  crypt
    mov   rcx, rsi
    mov   edx, [rdi+P_SELFLEN]
    mov   r8d, 0x811C9DC5
    call  checksum
    xor   [rdi+P_SEED], eax
    add   rsp, 0x20
    pop   rdi
    pop   rsi
    pop   rbx
tcRet:
    ret

crypt:
    push  rax
    push  rbx
    push  rsi
    push  rdi
    push  r10
    push  r11
    push  r12
    push  r13
    push  r14
    push  r15
    mov   rsi, rcx
    mov   r12d, edx
    mov   r13, r8
    mov   r14, r13
    mov   rax, 0xE0ACF1BBCDCBFA53
    rol   rax, 13
    xor   r14, rax
    mov   r15d, r9d
    xor   ebx, ebx
cryptLoop:
    cmp   ebx, r12d
    jae   cryptDone
    lea   ecx, [r15+rbx]
    shr   ecx, 3
    call  sipBlock
    mov   r11, rax
    lea   ecx, [r15+rbx]
    and   ecx, 7
    shl   ecx, 3
    shr   r11, cl
    xor   [rsi+rbx], r11b
    inc   ebx
    jmp   cryptLoop
cryptDone:
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    pop   r11
    pop   r10
    pop   rdi
    pop   rsi
    pop   rbx
    pop   rax
    ret

sipBlock:
    mov   r8, r13
    mov   rdx, 0xEAE6DEDACAE0E6CA
    rol   rdx, 7
    xor   r8, rdx
    mov   r9, r14
    mov   rdx, 0xEDAC8DEE4C2DCC8D
    rol   rdx, 11
    xor   r9, rdx
    mov   r10, r13
    mov   rdx, 0xAE4C2D8F2CECADCC
    rol   rdx, 19
    xor   r10, rdx
    mov   rax, r14
    mov   rdx, 0xE8CAE6E8CAC8C4F2
    rol   rdx, 23
    xor   rax, rdx
    xor   rax, rcx
    call  sipround
    call  sipround
    xor   r8, rcx
    mov   rdx, 0x0000000040000000
    rol   rdx, 29
    xor   rax, rdx
    call  sipround
    call  sipround
    mov   rdx, 0x0000000010000000
    rol   rdx, 31
    xor   r8, rdx
    xor   r10b, 0xFF
    call  sipround
    call  sipround
    call  sipround
    call  sipround
    xor   r8, r9
    xor   r8, r10
    xor   rax, r8
    ret

sipround:
    add   r8, r9
    rol   r9, 13
    xor   r9, r8
    rol   r8, 32
    add   r10, rax
    rol   rax, 16
    xor   rax, r10
    add   r8, rax
    rol   rax, 21
    xor   rax, r8
    add   r10, r9
    rol   r9, 17
    xor   r9, r10
    rol   r10, 32
    ret

deriveKey:
    push  rdx
    mov   eax, edx
    mov   rdx, 0xE0ACF1BBCDCBFA53
    rol   rdx, 13
    imul  rax, rdx
    xor   rax, rcx
    mov   rdx, rax
    shr   rdx, 30
    xor   rax, rdx
    mov   rdx, 0x72DCDFAC23B68E72
    rol   rdx, 17
    imul  rax, rdx
    mov   rdx, rax
    shr   rdx, 27
    xor   rax, rdx
    mov   rdx, 0xD899888F5CA6824D
    rol   rdx, 37
    imul  rax, rdx
    mov   rdx, rax
    shr   rdx, 31
    xor   rax, rdx
    or    rax, 1
    pop   rdx
    ret

vmEval:
    push  rsi
    push  rcx
    push  rdx
    push  r10
    push  r11
    mov   r10d, ecx
    lea   rsi, [rip+vmCode]
vmNext:
    movzx ecx, byte ptr [rsi]
    inc   rsi
    cmp   cl, 0x05
    je    vmLoadA
    cmp   cl, 0x04
    je    vmXorB
    cmp   cl, 0x02
    je    vmMul
    cmp   cl, 0x03
    je    vmXsh
    test  cl, cl
    jz    vmHalt
    jmp   vmNext
vmLoadA:
    mov   eax, r10d
    jmp   vmNext
vmXorB:
    xor   eax, edx
    jmp   vmNext
vmMul:
    mov   r11d, [rsi]
    add   rsi, 4
    xor   r11d, 0xA5A5A5A5
    imul  eax, r11d
    jmp   vmNext
vmXsh:
    movzx ecx, byte ptr [rsi]
    inc   rsi
    mov   r11d, eax
    shr   r11d, cl
    xor   eax, r11d
    jmp   vmNext
vmHalt:
    pop   r11
    pop   r10
    pop   rdx
    pop   rcx
    pop   rsi
    ret

vmCode:
    .byte 0x05
    .byte 0x02
    .long 0x3B92DC14
    .byte 0x04
    .byte 0x03
    .byte 15
    .byte 0x02
    .long 0x204E6FD2
    .byte 0x03
    .byte 13
    .byte 0x02
    .long 0x67170B98
    .byte 0x03
    .byte 16
    .byte 0x00

envHash:
    push  rbx
    push  rsi
    mov   rax, gs:[0x60]
    mov   rax, [rax+0x18]
    lea   rsi, [rax+0x10]
    mov   rbx, [rsi]
ehFind:
    cmp   rbx, rsi
    je    ehFail
    movzx eax, word ptr [rbx+0x58]
    cmp   eax, 18
    je    ehGot
    mov   rbx, [rbx]
    jmp   ehFind
ehGot:
    mov   rcx, [rbx+0x30]
    test  rcx, rcx
    jz    ehFail
    xor   eax, eax
    xor   edx, edx
ehLoop:
    cmp   edx, 60
    jae   ehDone
    rol   eax, 5
    movzx r8d, byte ptr [rcx+rdx]
    xor   eax, r8d
    inc   edx
    jmp   ehLoop
ehDone:
    pop   rsi
    pop   rbx
    ret
ehFail:
    xor   eax, eax
    pop   rsi
    pop   rbx
    ret

.balign 16
params:
    .fill 196, 1, 0
