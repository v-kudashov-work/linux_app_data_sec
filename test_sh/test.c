// run_script.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    // Запускаем скрипт в том же каталоге
    int ret = system("./test_sh.sh");

    if (ret == -1) {
        fprintf(stderr, "Failed to run script\n");
        return 1;
    }

    return 0;
}
