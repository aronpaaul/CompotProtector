// Differential VM fuzzer generator: emits fuzz.cpp with K marked functions
// of random VM-supported instructions. native vs protected must match.
#include <cstdio>
#include <cstdint>
#include <string>
using namespace std;

static unsigned st;
static unsigned rnd() { st = st * 1103515245u + 12345u; return st >> 1; }
static int rr(int n) { return (int)(rnd() % (unsigned)n); }

static const char* R64[6] = {"%%r8", "%%r9", "%%r10", "%%r11", "%%r12", "%%r13"};
static const char* R32[6] = {"%%r8d", "%%r9d", "%%r10d", "%%r11d", "%%r12d", "%%r13d"};
static const char* R16[6] = {"%%r8w", "%%r9w", "%%r10w", "%%r11w", "%%r12w", "%%r13w"};
static const char* R8L[6] = {"%%r8b", "%%r9b", "%%r10b", "%%r11b", "%%r12b", "%%r13b"};

static string op() {
    char b[160];
    int a = rr(6), c = rr(6);
    bool w = rr(2);
    const char** R = w ? R64 : R32;
    const char* s = w ? "q" : "l";
    const char* al[5] = {"add", "sub", "xor", "and", "or"};
    switch (rr(13)) {
        case 0: snprintf(b, 160, "%s%s %s, %s\\n", al[rr(5)], s, R[a], R[c]); break;
        case 1: snprintf(b, 160, "%s%s $%d, %s\\n", al[rr(5)], s, (int)(rnd() & 0x3ffff) - 0x20000, R[c]); break;
        case 2: { const char* sh[5] = {"shl", "shr", "sar", "rol", "ror"}; snprintf(b, 160, "%s%s $%d, %s\\n", sh[rr(5)], s, rr(w ? 64 : 32), R[c]); break; }
        case 3: { const char* u[4] = {"neg", "not", "inc", "dec"}; snprintf(b, 160, "%s%s %s\\n", u[rr(4)], s, R[c]); break; }
        case 4: snprintf(b, 160, "imul%s %s, %s\\n", s, R[a], R[c]); break;
        case 5: snprintf(b, 160, "mov%s %s, %s\\n", s, R[a], R[c]); break;
        case 6: snprintf(b, 160, "mov%s $%d, %s\\n", s, (int)(rnd() & 0x3ffff) - 0x20000, R[c]); break;
        case 7: { const char* cc[8] = {"e", "ne", "l", "ge", "le", "g", "b", "ae"}; snprintf(b, 160, "cmp%s %s, %s\\ncmov%s%s %s, %s\\n", s, R[a], R[c], cc[rr(8)], s, R[a], R[c]); break; }
        case 8: { int z = rr(2); const char** S = z ? R16 : R8L; char sc = z ? 'w' : 'b'; const char* mv = rr(2) ? "movz" : "movs"; snprintf(b, 160, "%s%c%s %s, %s\\n", mv, sc, w ? "q" : "l", S[a], R[c]); break; }
        case 9: snprintf(b, 160, "mov%s %d(%%0), %s\\n", s, rr(6) * 8, R[c]); break;
        case 10: snprintf(b, 160, "mov%s %s, %d(%%0)\\n", s, R[c], rr(6) * 8); break;
        case 11: snprintf(b, 160, "%s%s %s, %d(%%0)\\n", al[rr(5)], s, R[c], rr(6) * 8); break;
        case 12: { const char* u[4] = {"inc", "dec", "neg", "not"}; snprintf(b, 160, "%s%s %d(%%0)\\n", u[rr(4)], s, rr(6) * 8); break; }
    }
    return b;
}

int main(int argc, char** argv) {
    st = argc > 1 ? (unsigned)atoi(argv[1]) : 1;
    int K = argc>3?atoi(argv[3]):6;
    printf("#include <cstdio>\n#include <cstdint>\n");
    for (int k = 0; k < K; k++) {
        printf("__attribute__((noinline)) void f%d(uint64_t* v){asm volatile(\n", k);
        printf("\".byte 0xEB,0x08,0x56,0x4D,0x42,0x47,0x4E,0xCA,0xFE,0xBA\\n\"\n");
        for (int i = 0; i < 6; i++) printf("\"movq %d(%%0), %s\\n\"\n", i * 8, R64[i]);
        for (int i = 0, NN = argc>2?atoi(argv[2]):22; i < NN; i++) printf("\"%s\"\n", op().c_str());
        for (int i = 0; i < 6; i++) printf("\"movq %s, %d(%%0)\\n\"\n", R64[i], i * 8);
        printf("\".byte 0xEB,0x08,0x56,0x4D,0x45,0x4E,0x44,0xDE,0xC0,0xDE\\n\"\n");
        printf(": : \"r\"(v) : \"r8\",\"r9\",\"r10\",\"r11\",\"r12\",\"r13\",\"memory\",\"cc\");}\n");
    }
    printf("int main(){\n uint64_t base[6]={0x1111,0x2,0xFFFFFFFF80000000ULL,0x7F,0xDEADBEEF,0x40000000};\n");
    printf(" for(int s=0;s<6;s++){ for(int k=0;k<%d;k++){ uint64_t v[6]; for(int i=0;i<6;i++)v[i]=base[i]+s*0x101+k; ", K);
    printf("void(*fns[])(uint64_t*)={");
    for (int k = 0; k < K; k++) printf("f%d,", k);
    printf("}; fns[k](v); printf(\"%%d %%d %%016llX%%016llX%%016llX\\n\",s,k,(unsigned long long)(v[0]^v[3]),(unsigned long long)(v[1]^v[4]),(unsigned long long)(v[2]^v[5])); }}\n return 0;}\n");
    return 0;
}
