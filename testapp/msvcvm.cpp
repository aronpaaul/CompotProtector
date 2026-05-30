#define _CRT_SECURE_NO_WARNINGS
#include <cstdio>
__declspec(noinline) int vmDemo(int a, int b) {
    int r;
    __asm__ volatile(
        ".byte 0xEB,0x08,0x56,0x4D,0x42,0x47,0x4E,0xCA,0xFE,0xBA\n"
        "movl %1, %%eax\n"
        "addl %2, %%eax\n"
        "xorl $0x5A, %%eax\n"
        "imull $3, %%eax, %%eax\n"
        "movl %%eax, %0\n"
        ".byte 0xEB,0x08,0x56,0x4D,0x45,0x4E,0x44,0xDE,0xC0,0xDE\n"
        : "=r"(r) : "r"(a), "r"(b) : "eax");
    return r;
}
int main(){ for(int i=0;i<3;i++) printf("vmDemo(%d,%d)=%d\n", i*10, i+1, vmDemo(i*10, i+1)); return 0; }
