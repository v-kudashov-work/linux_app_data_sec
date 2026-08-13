#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>

#define TRACE_PIPE "/sys/kernel/debug/tracing/trace_pipe"
#define BUFFER_SIZE 4096

int main(int argc, char *argv[]) {
    int fd;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // Открываем системный журнал
    openlog("trace_pipe_reader", LOG_PID | LOG_CONS, LOG_DAEMON);
    syslog(LOG_INFO, "Trace pipe reader started");

    // Открываем trace_pipe
    fd = open(TRACE_PIPE, O_RDONLY);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open %s: %s", TRACE_PIPE, strerror(errno));
        closelog();
        return 1;
    }

    // Читаем и выводим в syslog
    while (1) {
        bytes_read = read(fd, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            // Удаляем перевод строки в конце, если есть
            if (bytes_read > 0 && buffer[bytes_read - 1] == '\n') {
                buffer[bytes_read - 1] = '\0';
            }
            syslog(LOG_INFO, "%s", buffer);
        } else if (bytes_read < 0) {
            if (errno != EINTR) {
                syslog(LOG_ERR, "Read error: %s", strerror(errno));
                break;
            }
        }
    }

    close(fd);
    closelog();
    return 0;
}
