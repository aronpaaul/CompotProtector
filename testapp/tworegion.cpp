#include <cstdio>
__attribute__((noinline)) int fa(int a, int b) {
    int r;
    asm volatile(
        ".byte 0xEB,0x08,0x56,0x4D,0x42,0x47,0x4E,0xCA,0xFE,0xBA\n"
        "movl %1, %%eax\n"
        "addl %2, %%eax\n"
        "shll $2, %%eax\n"
        "xorl $0x5A, %%eax\n"
        "cmpl $100, %%eax\n"
        "jle 1f\n"
        "subl $100, %%eax\n"
        "1:\n"
        "movl %%eax, %0\n"
        ".byte 0xEB,0x08,0x56,0x4D,0x45,0x4E,0x44,0xDE,0xC0,0xDE\n"
        : "=r"(r) : "r"(a), "r"(b) : "eax", "cc");
    return r;
}
__attribute__((noinline)) int fb(int a, int b) {
    int r;
    asm volatile(
        ".byte 0xEB,0x08,0x56,0x4D,0x42,0x47,0x4E,0xCA,0xFE,0xBA\n"
        "movl %1, %%eax\n"
        "imull $7, %%eax, %%eax\n"
        "andl %2, %%eax\n"
        "jz 1f\n"
        "orl $1, %%eax\n"
        "1:\n"
        "movl %%eax, %0\n"
        ".byte 0xEB,0x08,0x56,0x4D,0x45,0x4E,0x44,0xDE,0xC0,0xDE\n"
        : "=r"(r) : "r"(a), "r"(b) : "eax", "cc");
    return r;
}
int main(){
    for(int i=0;i<4;i++) printf("fa(%d,%d)=%d fb=%d\n", i*10, i+1, fa(i*10,i+1), fb(i*10,i+1));
    return 0;
}
