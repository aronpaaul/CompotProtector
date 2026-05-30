#include <cstdio>
#include <cstdlib>
#include <ctime>

int main() {
    srand((unsigned)time(0));
    unsigned char key = (unsigned char)(rand() & 0xFF);
    char secret[] = "compotprotector";
    for (int i = 0; secret[i]; i++) {
        secret[i] = (char)(secret[i] ^ key);
    }
    printf("hello my friend\n");
    printf("this is exe developed for testing compotprotector\n");
    printf("random generated key: 0x%02X\n", key);
    printf("press enter key to exit!\n");
    fflush(stdout);
    getchar();
    (void)secret;
    return 0;
}
