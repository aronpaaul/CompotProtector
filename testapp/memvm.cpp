#include <cstdio>
__attribute__((noinline)) int memDemo(int* a) {
    int r;
    asm volatile(
        ".byte 0xEB,0x08,0x56,0x4D,0x42,0x47,0x4E,0xCA,0xFE,0xBA\n"
        "movl (%1), %%eax\n"
        "addl 4(%1), %%eax\n"
        "imull $3, %%eax, %%eax\n"
        "movl %%eax, 8(%1)\n"
        "movl %%eax, %0\n"
        ".byte 0xEB,0x08,0x56,0x4D,0x45,0x4E,0x44,0xDE,0xC0,0xDE\n"
        : "=r"(r) : "r"(a) : "eax","memory");
    return r;
}
int main(){
    for(int i=0;i<3;i++){
        int a[3] = {i*10, i+1, -1};
        int r = memDemo(a);
        printf("memDemo({%d,%d}) = %d, a[2]=%d\n", a[0], a[1], r, a[2]);
    }
    return 0;
}
