// mkdir_example.c
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>

int main(int argc, char **argv) {
    // Проверяем аргументы
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <directory_path>\n", argv[0]);
        return 1;
    }

    // Создаем каталог с правами 0755 (rwxr-xr-x)
    if (mkdir(argv[1], 0755) == 0) {
        printf("Directory created: %s\n", argv[1]);
        return 0;
    } else {
        fprintf(stderr, "Failed to create directory %s: %s\n",
                argv[1], strerror(errno));
        return 1;
    }
}
