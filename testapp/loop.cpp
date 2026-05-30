#include <cstdio>
#include <windows.h>

static const char* watchedString = "ReencryptionWatchedSecretValue12345";

int main() {
    for (int iteration = 0; iteration < 40; ++iteration) {
        printf("[%02d] %s\n", iteration, watchedString);
        fflush(stdout);
        Sleep(150);
    }
    return 0;
}
