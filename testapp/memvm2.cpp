#include <cstdio>
__attribute__((noinline)) int f2(int* a, long i) {
    int r;
    asm volatile(
        ".byte 0xEB,0x08,0x56,0x4D,0x42,0x47,0x4E,0xCA,0xFE,0xBA\n"
        "movl $7, (%1,%q2,4)\n"
        "leaq (%1,%q2,4), %%rax\n"
        "movl (%%rax), %%edx\n"
        "addl $5, %%edx\n"
        "movl %%edx, %0\n"
        ".byte 0xEB,0x08,0x56,0x4D,0x45,0x4E,0x44,0xDE,0xC0,0xDE\n"
        : "=r"(r) : "r"(a), "r"(i) : "rax","rdx","memory");
    return r;
}
int main(){
    for(long i=0;i<3;i++){
        int a[4] = {-1,-1,-1,-1};
        int r = f2(a, i);
        printf("f2(i=%ld) r=%d a[%ld]=%d\n", i, r, i, a[i]);
    }
    return 0;
}
