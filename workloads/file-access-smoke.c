/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#define CHECK(expression) do { if (!(expression)) { \
    fprintf(stderr, "file-access fixture failed at line %d: %s (errno=%d)\n", \
            __LINE__, #expression, errno); return 1; } } while (0)

int main(int argc, char **argv)
{
    char first[512], second[512], alias[512], buffer[32] = {0};
    struct iovec vectors[2] = {{buffer, 2}, {buffer + 2, 3}};
    int a, b, inherited;

    CHECK(argc == 2);
    CHECK(snprintf(first, sizeof(first), "%s/a", argv[1]) < (int)sizeof(first));
    CHECK(snprintf(second, sizeof(second), "%s/b", argv[1]) < (int)sizeof(second));
    CHECK(snprintf(alias, sizeof(alias), "%s/alias", argv[1]) < (int)sizeof(alias));
    CHECK(mkdir(argv[1], 0700) == 0);
    a = open(first, O_CREAT | O_RDWR | O_EXCL, 0600);
    CHECK(a >= 0);
    CHECK(write(a, "abcdefgh", 8) == 8);
    CHECK(pwrite(a, "XY", 2, 2) == 2);
    CHECK(writev(a, vectors, 2) == 5);
    CHECK(pwritev(a, vectors, 2, 0) == 5);
    CHECK(syscall(SYS_pwritev2, a, vectors, 2, 0L, 0L, 0) == 5);
    CHECK(lseek(a, 0, SEEK_SET) == 0);
    CHECK(read(a, buffer, sizeof(buffer)) == 13); /* short read */
    CHECK(read(a, buffer, sizeof(buffer)) == 0);  /* EOF */
    CHECK(pread(a, buffer, 4, 1) == 4);
    CHECK(lseek(a, 0, SEEK_SET) == 0);
    CHECK(readv(a, vectors, 2) == 5);
    CHECK(preadv(a, vectors, 2, 0) == 5);
    CHECK(syscall(SYS_preadv2, a, vectors, 2, 0L, 0L, 0) == 5);
    CHECK(link(first, alias) == 0);
    inherited = dup(a);
    CHECK(inherited >= 0);
    CHECK(pread(inherited, buffer, 3, 0) == 3);
    CHECK(close(inherited) == 0);
    CHECK(close(a) == 0);
    a = open(alias, O_RDONLY); /* ordinary open, same inode */
    CHECK(a >= 0);
    CHECK(read(a, buffer, 2) == 2);
    CHECK(close(a) == 0);
    b = open(second, O_CREAT | O_RDWR | O_EXCL, 0600); /* fd reuse */
    CHECK(b >= 0);
    CHECK(write(b, "123", 3) == 3);
    CHECK(pread(b, buffer, 9, 0) == 3);
    CHECK(close(b) == 0);
    CHECK(read(b, buffer, 1) == -1 && errno == EBADF);
    CHECK(open("/no-such-file-access-fixture", O_RDONLY) == -1 && errno == ENOENT);
    CHECK(write(STDOUT_FILENO, "FILE_ACCESS_FIXTURE_OK\n", 23) == 23);
    return 0;
}
