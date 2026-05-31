#include <cstdio>
__attribute__((noinline)) int f(int a, int b) {
    int r;
    asm volatile(
        ".byte 0xEB,0x08,0x56,0x4D,0x42,0x47,0x4E,0xCA,0xFE,0xBA\n"
        "movl %1, %%eax\n"
        "andl %2, %%eax\n"
        "jz 1f\n"
        "movl $111, %%eax\n"
        "jmp 2f\n"
        "1:\n"
        "movl $222, %%eax\n"
        "2:\n"
        "movl %%eax, %0\n"
        ".byte 0xEB,0x08,0x56,0x4D,0x45,0x4E,0x44,0xDE,0xC0,0xDE\n"
        : "=r"(r) : "r"(a), "r"(b) : "eax", "cc");
    return r;
}
int main(){
    int t[][2]={{0xF0,0x0F},{0xFF,0x01},{12,8},{5,2},{0,99}};
    for(auto&x:t) printf("f(%d,%d)=%d\n",x[0],x[1],f(x[0],x[1]));
    return 0;
}
