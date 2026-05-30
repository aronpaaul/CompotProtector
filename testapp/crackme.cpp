#define _CRT_SECURE_NO_WARNINGS
#include <cstdio>
#include <cstring>

int main() {
    char key[64] = {0};
    printf("hello my friend\n");
    printf("this is crackme\n");
    printf("for custom packer \"CompotProtector\"\n");
    printf("enter the key\n");
    printf("> ");
    fflush(stdout);
    if (scanf("%63s", key) != 1) {
        return 0;
    }
    if (strcmp(key, "handcorrect") == 0) {
        printf("yesofcourse\n");
    } else {
        printf("nononoooo\n");
    }
    return 0;
}
