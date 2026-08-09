// test_app_data_sec.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#define TEST_DIR "~/.app_data_sec_test"
#define CONFIG_FILE "/etc/app_data_sec.conf"
#define CONFIG_BACKUP "/etc/app_data_sec.conf.bak"

// Цвета для вывода
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_RESET   "\033[0m"

int test_passed = 0;
int test_failed = 0;

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ============================================================================

static void print_test_header(const char *name) {
    printf("\n%s========================================%s\n", COLOR_BLUE, COLOR_RESET);
    printf("%sTEST: %s%s\n", COLOR_YELLOW, name, COLOR_RESET);
    printf("%s========================================%s\n", COLOR_BLUE, COLOR_RESET);
}

static void print_test_result(int passed, const char *msg) {
    if (passed) {
        printf("%s  [PASS]%s %s\n", COLOR_GREEN, COLOR_RESET, msg);
        test_passed++;
    } else {
        printf("%s  [FAIL]%s %s\n", COLOR_RED, COLOR_RESET, msg);
        test_failed++;
    }
}

// Разворачивание ~ в путь
static char* expand_tilde(const char *path) {
    static char expanded[PATH_MAX];
    if (path[0] != '~') {
        strcpy(expanded, path);
        return expanded;
    }

    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) {
            home = pw->pw_dir;
        }
    }
    if (!home) {
        return NULL;
    }

    snprintf(expanded, sizeof(expanded), "%s%s", home, path + 1);
    return expanded;
}

// Создание директории
static int create_dir(const char *path) {
    char *full_path = expand_tilde(path);
    if (!full_path) return -1;

    struct stat st;
    if (stat(full_path, &st) == 0) {
        return 0;  // уже существует
    }

    // Создаём рекурсивно
    char tmp[PATH_MAX];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", full_path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return mkdir(tmp, 0755);
}

// Удаление директории рекурсивно
static int remove_dir(const char *path) {
    char *full_path = expand_tilde(path);
    if (!full_path) return -1;

    char cmd[PATH_MAX + 100];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", full_path);
    return system(cmd);
}

// Создание файла
static int create_file(const char *path, const char *content) {
    char *full_path = expand_tilde(path);
    if (!full_path) return -1;

    FILE *f = fopen(full_path, "w");
    if (!f) return -1;
    fprintf(f, "%s", content);
    fclose(f);
    return 0;
}

// Проверка существования файла/директории
static int exists(const char *path) {
    char *full_path = expand_tilde(path);
    if (!full_path) return 0;
    struct stat st;
    return (stat(full_path, &st) == 0);
}

// Чтение содержимого директории
static int read_dir(const char *path, char **files, int max_files) {
    char *full_path = expand_tilde(path);
    if (!full_path) return -1;

    DIR *dir = opendir(full_path);
    if (!dir) return -1;

    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(dir)) != NULL && count < max_files) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        files[count] = strdup(entry->d_name);
        count++;
    }
    closedir(dir);
    return count;
}

// Сохранение конфига
static int save_config(const char *content) {
    FILE *f = fopen(CONFIG_FILE, "w");
    if (!f) return -1;
    fprintf(f, "%s", content);
    fclose(f);
    return 0;
}

// Чтение конфига
static char* read_config(void) {
    static char content[4096];
    FILE *f = fopen(CONFIG_FILE, "r");
    if (!f) return NULL;

    size_t len = fread(content, 1, sizeof(content) - 1, f);
    content[len] = '\0';
    fclose(f);
    return content;
}

// Бэкап конфига
static int backup_config(void) {
    char cmd[PATH_MAX + 100];
    snprintf(cmd, sizeof(cmd), "cp %s %s", CONFIG_FILE, CONFIG_BACKUP);
    return system(cmd);
}

// Восстановление конфига
static int restore_config(void) {
    char cmd[PATH_MAX + 100];
    snprintf(cmd, sizeof(cmd), "cp %s %s", CONFIG_BACKUP, CONFIG_FILE);
    return system(cmd);
}

// Проверка доступа к папке (чтение)
static int can_access_folder(const char *path) {
    char *full_path = expand_tilde(path);
    if (!full_path) return 0;

    DIR *dir = opendir(full_path);
    if (!dir) {
        return 0;  // Нет доступа
    }
    closedir(dir);
    return 1;  // Есть доступ
}

// Проверка доступа к файлу (чтение)
static int can_access_file(const char *path) {
    char *full_path = expand_tilde(path);
    if (!full_path) return 0;

    FILE *f = fopen(full_path, "r");
    if (!f) {
        return 0;
    }
    fclose(f);
    return 1;
}

// Запуск программы для теста доступа
static int test_access_from_program(const char *program_path, const char *target_path) {
    char cmd[PATH_MAX + 200];
    snprintf(cmd, sizeof(cmd), "%s %s 2>/dev/null", program_path, target_path);
    int result = system(cmd);
    return (result == 0);
}

// ============================================================================
// ТЕСТОВЫЕ ПРОГРАММЫ (создаются на лету)
// ============================================================================

static int create_test_programs(void) {
    const char *test_app1 =
        "#!/bin/bash\n"
        "if [ -z \"$1\" ]; then\n"
        "    echo \"Usage: $0 <path>\"\n"
        "    exit 1\n"
        "fi\n"
        "ls -la \"$1\" 2>/dev/null && echo \"ACCESS_GRANTED\" || echo \"ACCESS_DENIED\"\n";

    const char *test_app2 =
        "#!/bin/bash\n"
        "if [ -z \"$1\" ]; then\n"
        "    echo \"Usage: $0 <path>\"\n"
        "    exit 1\n"
        "fi\n"
        "ls -la \"$1\" 2>/dev/null && echo \"ACCESS_GRANTED\" || echo \"ACCESS_DENIED\"\n";

    // Создаём тестовые программы в /tmp
    FILE *f = fopen("/tmp/test_app1", "w");
    if (!f) return -1;
    fprintf(f, "%s", test_app1);
    fclose(f);
    chmod("/tmp/test_app1", 0755);

    f = fopen("/tmp/test_app2", "w");
    if (!f) return -1;
    fprintf(f, "%s", test_app2);
    fclose(f);
    chmod("/tmp/test_app2", 0755);

    return 0;
}

static void cleanup_test_programs(void) {
    unlink("/tmp/test_app1");
    unlink("/tmp/test_app2");
}

// ============================================================================
// ТЕСТ 1: Папка создана до конфига
// ============================================================================

static int test1_folder_before_config(void) {
    print_test_header("Test 1: Folder created before config");

    int passed = 1;
    const char *test_folder = "~/.app_data_sec_test/folder1";
    const char *test_file = "~/.app_data_sec_test/folder1/test.txt";
    char full_test_folder[PATH_MAX];
    char full_test_file[PATH_MAX];

    // Получаем полные пути
    char *tf = expand_tilde(test_folder);
    char *tfile = expand_tilde(test_file);
    strcpy(full_test_folder, tf);
    strcpy(full_test_file, tfile);

    // 1. Создаём тестовую папку и файл
    printf("  Creating test folder and file...\n");
    create_dir(test_folder);
    create_file(test_file, "Test content");

    if (!exists(test_folder) || !exists(test_file)) {
        print_test_result(0, "Failed to create test folder/file");
        return 0;
    }
    print_test_result(1, "Test folder and file created");

    // 2. Настраиваем конфиг
    printf("  Configuring protection...\n");
    char config[1024];
    snprintf(config, sizeof(config),
        "enable = yes\n"
        "protect %s /tmp/test_app1\n", full_test_folder);
    save_config(config);
    sleep(5);  // Ждём перезагрузки конфига

    // 3. Проверяем доступ из test_app1 (должен быть разрешён)
    printf("  Testing access from test_app1 (should be ALLOWED)...\n");
    int result = system("/tmp/test_app1 " full_test_folder " | grep -q ACCESS_GRANTED");
    if (result == 0) {
        print_test_result(1, "test_app1 can access folder");
    } else {
        print_test_result(0, "test_app1 CANNOT access folder");
        passed = 0;
    }

    // 4. Проверяем доступ из test_app2 (должен быть запрещён)
    printf("  Testing access from test_app2 (should be DENIED)...\n");
    result = system("/tmp/test_app2 " full_test_folder " | grep -q ACCESS_GRANTED");
    if (result != 0) {
        print_test_result(1, "test_app2 cannot access folder");
    } else {
        print_test_result(0, "test_app2 CAN access folder");
        passed = 0;
    }

    // 5. Проверяем доступ к файлу внутри папки из test_app1
    printf("  Testing file access from test_app1 (should be ALLOWED)...\n");
    result = system("/tmp/test_app1 " full_test_file " | grep -q ACCESS_GRANTED");
    if (result == 0) {
        print_test_result(1, "test_app1 can access file inside folder");
    } else {
        print_test_result(0, "test_app1 CANNOT access file inside folder");
        passed = 0;
    }

    // 6. Проверяем доступ к файлу из test_app2 (должен быть запрещён)
    printf("  Testing file access from test_app2 (should be DENIED)...\n");
    result = system("/tmp/test_app2 " full_test_file " | grep -q ACCESS_GRANTED");
    if (result != 0) {
        print_test_result(1, "test_app2 cannot access file inside folder");
    } else {
        print_test_result(0, "test_app2 CAN access file inside folder");
        passed = 0;
    }

    // 7. Очистка
    printf("  Cleaning up...\n");
    remove_dir(test_folder);

    return passed;
}

// ============================================================================
// ТЕСТ 2: Конфиг до создания папки
// ============================================================================

static int test2_config_before_folder(void) {
    print_test_header("Test 2: Config before folder creation");

    int passed = 1;
    const char *test_folder = "~/.app_data_sec_test/folder2";
    const char *test_file = "~/.app_data_sec_test/folder2/test.txt";
    char full_test_folder[PATH_MAX];

    char *tf = expand_tilde(test_folder);
    strcpy(full_test_folder, tf);

    // 1. Убеждаемся, что папки нет
    printf("  Ensuring folder does not exist...\n");
    remove_dir(test_folder);

    // 2. Настраиваем конфиг
    printf("  Configuring protection before folder creation...\n");
    char config[1024];
    snprintf(config, sizeof(config),
        "enable = yes\n"
        "protect %s /tmp/test_app1\n", full_test_folder);
    save_config(config);
    sleep(5);

    // 3. Проверяем, что папка не существует
    printf("  Verifying folder does not exist...\n");
    if (!exists(test_folder)) {
        print_test_result(1, "Folder does not exist as expected");
    } else {
        print_test_result(0, "Folder exists but shouldn't");
        passed = 0;
    }

    // 4. Создаём папку
    printf("  Creating folder...\n");
    create_dir(test_folder);
    create_file(test_file, "Test content");
    sleep(30);  // Ждём сканирования новых папок

    if (!exists(test_folder) || !exists(test_file)) {
        print_test_result(0, "Failed to create test folder/file");
        return 0;
    }
    print_test_result(1, "Test folder and file created");

    // 5. Проверяем доступ из test_app1 (должен быть разрешён)
    printf("  Testing access from test_app1 (should be ALLOWED)...\n");
    int result = system("/tmp/test_app1 " full_test_folder " | grep -q ACCESS_GRANTED");
    if (result == 0) {
        print_test_result(1, "test_app1 can access folder");
    } else {
        print_test_result(0, "test_app1 CANNOT access folder");
        passed = 0;
    }

    // 6. Проверяем доступ из test_app2 (должен быть запрещён)
    printf("  Testing access from test_app2 (should be DENIED)...\n");
    result = system("/tmp/test_app2 " full_test_folder " | grep -q ACCESS_GRANTED");
    if (result != 0) {
        print_test_result(1, "test_app2 cannot access folder");
    } else {
        print_test_result(0, "test_app2 CAN access folder");
        passed = 0;
    }

    // 7. Очистка
    printf("  Cleaning up...\n");
    remove_dir(test_folder);

    return passed;
}

// ============================================================================
// ТЕСТ 3: Проверка с ~ в конфиге
// ============================================================================

static int test3_tilde_in_config(void) {
    print_test_header("Test 3: Tilde expansion in config");

    int passed = 1;
    const char *test_folder = "~/.app_data_sec_test/folder3";
    const char *test_file = "~/.app_data_sec_test/folder3/test.txt";
    char full_test_folder[PATH_MAX];

    char *tf = expand_tilde(test_folder);
    strcpy(full_test_folder, tf);

    // 1. Создаём папку
    printf("  Creating test folder...\n");
    create_dir(test_folder);
    create_file(test_file, "Test content");

    if (!exists(test_folder) || !exists(test_file)) {
        print_test_result(0, "Failed to create test folder/file");
        return 0;
    }
    print_test_result(1, "Test folder and file created");

    // 2. Настраиваем конфиг с ~
    printf("  Configuring with ~ in path...\n");
    char config[1024];
    snprintf(config, sizeof(config),
        "enable = yes\n"
        "protect ~/.app_data_sec_test/folder3 /tmp/test_app1\n");
    save_config(config);
    sleep(5);

    // 3. Проверяем доступ из test_app1 (должен быть разрешён)
    printf("  Testing access from test_app1 (should be ALLOWED)...\n");
    int result = system("/tmp/test_app1 " full_test_folder " | grep -q ACCESS_GRANTED");
    if (result == 0) {
        print_test_result(1, "test_app1 can access folder with ~ path");
    } else {
        print_test_result(0, "test_app1 CANNOT access folder with ~ path");
        passed = 0;
    }

    // 4. Проверяем доступ из test_app2 (должен быть запрещён)
    printf("  Testing access from test_app2 (should be DENIED)...\n");
    result = system("/tmp/test_app2 " full_test_folder " | grep -q ACCESS_GRANTED");
    if (result != 0) {
        print_test_result(1, "test_app2 cannot access folder with ~ path");
    } else {
        print_test_result(0, "test_app2 CAN access folder with ~ path");
        passed = 0;
    }

    // 5. Очистка
    printf("  Cleaning up...\n");
    remove_dir(test_folder);

    return passed;
}

// ============================================================================
// ТЕСТ 4: Проверка вложенных папок
// ============================================================================

static int test4_nested_folders(void) {
    print_test_header("Test 4: Nested folders protection");

    int passed = 1;
    const char *base_folder = "~/.app_data_sec_test/nested";
    const char *sub_folder = "~/.app_data_sec_test/nested/sub";
    const char *test_file = "~/.app_data_sec_test/nested/sub/test.txt";
    char full_base[PATH_MAX];

    char *bf = expand_tilde(base_folder);
    strcpy(full_base, bf);

    // 1. Создаём вложенные папки и файл
    printf("  Creating nested folders and file...\n");
    create_dir(sub_folder);
    create_file(test_file, "Test content");

    if (!exists(sub_folder) || !exists(test_file)) {
        print_test_result(0, "Failed to create nested folders/file");
        return 0;
    }
    print_test_result(1, "Nested folders and file created");

    // 2. Защищаем только базовую папку
    printf("  Protecting base folder only...\n");
    char config[1024];
    snprintf(config, sizeof(config),
        "enable = yes\n"
        "protect %s /tmp/test_app1\n", full_base);
    save_config(config);
    sleep(5);

    // 3. Проверяем доступ к подпапке из test_app1 (должен быть разрешён)
    printf("  Testing subfolder access from test_app1 (should be ALLOWED)...\n");
    char cmd[PATH_MAX + 200];
    char *sf = expand_tilde(sub_folder);
    snprintf(cmd, sizeof(cmd), "/tmp/test_app1 %s | grep -q ACCESS_GRANTED", sf);
    int result = system(cmd);
    if (result == 0) {
        print_test_result(1, "test_app1 can access subfolder");
    } else {
        print_test_result(0, "test_app1 CANNOT access subfolder");
        passed = 0;
    }

    // 4. Проверяем доступ из test_app2 (должен быть запрещён)
    printf("  Testing subfolder access from test_app2 (should be DENIED)...\n");
    snprintf(cmd, sizeof(cmd), "/tmp/test_app2 %s | grep -q ACCESS_GRANTED", sf);
    result = system(cmd);
    if (result != 0) {
        print_test_result(1, "test_app2 cannot access subfolder");
    } else {
        print_test_result(0, "test_app2 CAN access subfolder");
        passed = 0;
    }

    // 5. Очистка
    printf("  Cleaning up...\n");
    remove_dir(base_folder);

    return passed;
}

// ============================================================================
// ТЕСТ 5: Удаление папки из конфига
// ============================================================================

static int test5_remove_from_config(void) {
    print_test_header("Test 5: Remove folder from config");

    int passed = 1;
    const char *test_folder = "~/.app_data_sec_test/folder5";
    const char *test_file = "~/.app_data_sec_test/folder5/test.txt";
    char full_test_folder[PATH_MAX];

    char *tf = expand_tilde(test_folder);
    strcpy(full_test_folder, tf);

    // 1. Создаём папку и защищаем её
    printf("  Creating test folder and protecting it...\n");
    create_dir(test_folder);
    create_file(test_file, "Test content");

    char config[1024];
    snprintf(config, sizeof(config),
        "enable = yes\n"
        "protect %s /tmp/test_app1\n", full_test_folder);
    save_config(config);
    sleep(5);

    // 2. Проверяем, что доступ запрещён для test_app2
    printf("  Verifying folder is protected...\n");
    int result = system("/tmp/test_app2 " full_test_folder " | grep -q ACCESS_GRANTED");
    if (result != 0) {
        print_test_result(1, "Folder is protected");
    } else {
        print_test_result(0, "Folder is NOT protected");
        passed = 0;
    }

    // 3. Удаляем папку из конфига
    printf("  Removing folder from config...\n");
    snprintf(config, sizeof(config),
        "enable = yes\n");
    save_config(config);
    sleep(5);

    // 4. Проверяем, что доступ стал открытым для test_app2
    printf("  Testing access after removal (should be ALLOWED)...\n");
    result = system("/tmp/test_app2 " full_test_folder " | grep -q ACCESS_GRANTED");
    if (result == 0) {
        print_test_result(1, "Folder is accessible after removal from config");
    } else {
        print_test_result(0, "Folder is STILL protected after removal");
        passed = 0;
    }

    // 5. Очистка
    printf("  Cleaning up...\n");
    remove_dir(test_folder);

    return passed;
}

// ============================================================================
// ТЕСТ 6: Множественные папки и программы
// ============================================================================

static int test6_multiple_folders_programs(void) {
    print_test_header("Test 6: Multiple folders and programs");

    int passed = 1;
    const char *folder1 = "~/.app_data_sec_test/multi1";
    const char *folder2 = "~/.app_data_sec_test/multi2";
    char full1[PATH_MAX], full2[PATH_MAX];

    char *f1 = expand_tilde(folder1);
    char *f2 = expand_tilde(folder2);
    strcpy(full1, f1);
    strcpy(full2, f2);

    // 1. Создаём папки
    printf("  Creating test folders...\n");
    create_dir(folder1);
    create_dir(folder2);
    create_file("~/.app_data_sec_test/multi1/test1.txt", "Content 1");
    create_file("~/.app_data_sec_test/multi2/test2.txt", "Content 2");

    print_test_result(1, "Test folders created");

    // 2. Конфиг: две папки с разными разрешёнными программами
    printf("  Configuring multiple protections...\n");
    char config[2048];
    snprintf(config, sizeof(config),
        "enable = yes\n"
        "protect %s /tmp/test_app1\n"
        "protect %s /tmp/test_app2\n", full1, full2);
    save_config(config);
    sleep(5);

    // 3. Проверяем доступ
    int result1 = system("/tmp/test_app1 " full1 " | grep -q ACCESS_GRANTED");
    int result2 = system("/tmp/test_app2 " full1 " | grep -q ACCESS_GRANTED");
    int result3 = system("/tmp/test_app1 " full2 " | grep -q ACCESS_GRANTED");
    int result4 = system("/tmp/test_app2 " full2 " | grep -q ACCESS_GRANTED");

    if (result1 == 0) print_test_result(1, "test_app1 can access folder1");
    else { print_test_result(0, "test_app1 CANNOT access folder1"); passed = 0; }

    if (result2 != 0) print_test_result(1, "test_app2 cannot access folder1");
    else { print_test_result(0, "test_app2 CAN access folder1"); passed = 0; }

    if (result3 != 0) print_test_result(1, "test_app1 cannot access folder2");
    else { print_test_result(0, "test_app1 CAN access folder2"); passed = 0; }

    if (result4 == 0) print_test_result(1, "test_app2 can access folder2");
    else { print_test_result(0, "test_app2 CANNOT access folder2"); passed = 0; }

    // 4. Очистка
    printf("  Cleaning up...\n");
    remove_dir("~/.app_data_sec_test/multi1");
    remove_dir("~/.app_data_sec_test/multi2");

    return passed;
}

// ============================================================================
// ТЕСТ 7: Стресс-тест (много операций)
// ============================================================================

static int test7_stress(void) {
    print_test_header("Test 7: Stress test");

    int passed = 1;
    const char *test_folder = "~/.app_data_sec_test/stress";
    char full_test_folder[PATH_MAX];

    char *tf = expand_tilde(test_folder);
    strcpy(full_test_folder, tf);

    // 1. Защищаем папку
    printf("  Protecting folder...\n");
    char config[1024];
    snprintf(config, sizeof(config),
        "enable = yes\n"
        "protect %s /tmp/test_app1\n", full_test_folder);
    save_config(config);
    sleep(5);

    // 2. Создаём 100 файлов
    printf("  Creating 100 files...\n");
    create_dir(test_folder);
    for (int i = 0; i < 100; i++) {
        char fpath[PATH_MAX];
        snprintf(fpath, sizeof(fpath), "~/.app_data_sec_test/stress/file_%d.txt", i);
        create_file(fpath, "Stress test content");
    }
    sleep(30);  // Ждём сканирования

    // 3. Проверяем, что все файлы скрыты для test_app2
    printf("  Verifying files are hidden from test_app2...\n");
    int hidden = 1;
    for (int i = 0; i < 10; i++) {
        char fpath[PATH_MAX];
        snprintf(fpath, sizeof(fpath), "%s/file_%d.txt", full_test_folder, i);
        char cmd[PATH_MAX + 200];
        snprintf(cmd, sizeof(cmd), "/tmp/test_app2 %s | grep -q ACCESS_GRANTED", fpath);
        if (system(cmd) == 0) {
            hidden = 0;
            break;
        }
    }

    if (hidden) {
        print_test_result(1, "All files are hidden from test_app2");
    } else {
        print_test_result(0, "Some files are visible to test_app2");
        passed = 0;
    }

    // 4. Проверяем доступ для test_app1
    printf("  Verifying test_app1 can access files...\n");
    char cmd[PATH_MAX + 200];
    snprintf(cmd, sizeof(cmd), "/tmp/test_app1 %s/file_0.txt | grep -q ACCESS_GRANTED", full_test_folder);
    if (system(cmd) == 0) {
        print_test_result(1, "test_app1 can access files");
    } else {
        print_test_result(0, "test_app1 CANNOT access files");
        passed = 0;
    }

    // 5. Очистка
    printf("  Cleaning up...\n");
    remove_dir(test_folder);

    return passed;
}

// ============================================================================
// ГЛАВНАЯ ФУНКЦИЯ
// ============================================================================

int main(int argc, char **argv) {
    printf("%s========================================%s\n", COLOR_BLUE, COLOR_RESET);
    printf("%s   APP DATA SEC - TEST SUITE%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("%s========================================%s\n", COLOR_BLUE, COLOR_RESET);
    printf("Test directory: ~/.app_data_sec_test/\n");
    printf("Config file: %s\n\n", CONFIG_FILE);

    // Проверяем права root
    if (geteuid() != 0) {
        printf("%sERROR: This test must be run as root (sudo)%s\n", COLOR_RED, COLOR_RESET);
        return 1;
    }

    // Создаём тестовые программы
    if (create_test_programs() != 0) {
        printf("%sERROR: Failed to create test programs%s\n", COLOR_RED, COLOR_RESET);
        return 1;
    }

    // Создаём тестовую директорию
    create_dir("~/.app_data_sec_test");

    // Бэкапим конфиг
    backup_config();

    // Запускаем тесты
    int results[7];

    results[0] = test1_folder_before_config();
    results[1] = test2_config_before_folder();
    results[2] = test3_tilde_in_config();
    results[3] = test4_nested_folders();
    results[4] = test5_remove_from_config();
    results[5] = test6_multiple_folders_programs();
    results[6] = test7_stress();

    // Итоги
    printf("\n%s========================================%s\n", COLOR_BLUE, COLOR_RESET);
    printf("%s              RESULTS%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("%s========================================%s\n", COLOR_BLUE, COLOR_RESET);
    printf("Test 1: Folder before config: %s%s%s\n",
           results[0] ? COLOR_GREEN : COLOR_RED,
           results[0] ? "PASS" : "FAIL",
           COLOR_RESET);
    printf("Test 2: Config before folder: %s%s%s\n",
           results[1] ? COLOR_GREEN : COLOR_RED,
           results[1] ? "PASS" : "FAIL",
           COLOR_RESET);
    printf("Test 3: Tilde in config: %s%s%s\n",
           results[2] ? COLOR_GREEN : COLOR_RED,
           results[2] ? "PASS" : "FAIL",
           COLOR_RESET);
    printf("Test 4: Nested folders: %s%s%s\n",
           results[3] ? COLOR_GREEN : COLOR_RED,
           results[3] ? "PASS" : "FAIL",
           COLOR_RESET);
    printf("Test 5: Remove from config: %s%s%s\n",
           results[4] ? COLOR_GREEN : COLOR_RED,
           results[4] ? "PASS" : "FAIL",
           COLOR_RESET);
    printf("Test 6: Multiple folders/programs: %s%s%s\n",
           results[5] ? COLOR_GREEN : COLOR_RED,
           results[5] ? "PASS" : "FAIL",
           COLOR_RESET);
    printf("Test 7: Stress test: %s%s%s\n",
           results[6] ? COLOR_GREEN : COLOR_RED,
           results[6] ? "PASS" : "FAIL",
           COLOR_RESET);

    printf("\nTotal: %s%d PASSED%s, %s%d FAILED%s\n",
           COLOR_GREEN, test_passed, COLOR_RESET,
           COLOR_RED, test_failed, COLOR_RESET);

    // Очистка
    restore_config();
    cleanup_test_programs();
    remove_dir("~/.app_data_sec_test");

    return (test_failed == 0) ? 0 : 1;
}
