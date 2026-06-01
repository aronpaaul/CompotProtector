#include <cstdio>
__attribute__((noinline)) int newDemo(unsigned char* b, int* w, int sel) {
    int r;
    asm volatile(
        ".byte 0xEB,0x08,0x56,0x4D,0x42,0x47,0x4E,0xCA,0xFE,0xBA\n"
        "movzbl (%1), %%eax\n"
        "movsbl 1(%1), %%edx\n"
        "addl %%edx, %%eax\n"
        "addl %%eax, (%2)\n"
        "xchg %%eax, %%edx\n"
        "movl %%edx, %%eax\n"
        "cmpl $0, %3\n"
        "movl $100, %%edx\n"
        "cmovgl %%edx, %%eax\n"
        "incl (%2)\n"
        "movl %%eax, %0\n"
        ".byte 0xEB,0x08,0x56,0x4D,0x45,0x4E,0x44,0xDE,0xC0,0xDE\n"
        : "=r"(r) : "r"(b), "r"(w), "r"(sel) : "eax","edx","cc","memory");
    return r;
}
int main(){
    for(int s=-1;s<=1;s++){
        unsigned char b[2] = {200, (unsigned char)-5};
        int w[1] = {1000};
        int r = newDemo(b, w, s);
        printf("sel=%d r=%d w[0]=%d\n", s, r, w[0]);
    }
    return 0;
}
