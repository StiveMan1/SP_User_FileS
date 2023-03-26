#include "userfs.h"
#include <stddef.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

enum {
	BLOCK_SIZE = 512,
	MAX_FILE_SIZE = 1024 * 1024 * 1024,
};

/** Global error code. Set from any function on any error. */
static enum ufs_error_code ufs_error_code = UFS_ERR_NO_ERR;

struct block {
	/** Block memory. */
	char *memory;
	/** How many bytes are occupied. */
	int occupied;
	/** Next block in the file. */
	struct block *next;
	/** Previous block in the file. */
	struct block *prev;

	/* PUT HERE OTHER MEMBERS */
};

struct file {
	/** Double-linked list of file blocks. */
	struct block *block_list;
	/**
	 * Last block in the list above for fast access to the end
	 * of file.
	 */
	struct block *last_block;
	/** How many file descriptors are opened on the file. */
	int refs;
	/** File name. */
	char *name;
	/** Files are stored in a double-linked list. */
	struct file *next;
	struct file *prev;

    /** File deleting flag. */
    int delete;

	/* PUT HERE OTHER MEMBERS */
};

/** List of all files. */
static struct file *file_list = NULL;

struct file *file_find(const char *filename) {
    size_t name_size = strlen(filename);
    struct file *ptr = file_list;
    while (ptr != NULL) {
        if (!ptr->delete && name_size == strlen(ptr->name) && memcmp(filename, ptr->name, name_size) == 0) {
            ptr->refs++;
            return ptr;
        }
        ptr = ptr->next;
    }
    return NULL;
}
struct file *file_create(const char *filename) {
    struct file *res = malloc(sizeof(struct file));
    res->block_list = res->last_block = NULL;

    res->refs = 1;
    res->delete = 0;
    res->name = malloc(strlen(filename) + 1);
    memcpy(res->name, filename, strlen(filename) + 1);

    res->prev = NULL;
    res->next = file_list;
    if (file_list != NULL) file_list->prev = res;
    file_list = res;

    return res;
}
void file_resize(struct file *res, size_t new_size) {
    struct block *ptr = res->block_list;
    struct block *temp = NULL;
    size_t size = 0, add = 0;

    while (size < new_size) {
        if (ptr == NULL) {
            ptr = malloc(sizeof(struct block));
            ptr->occupied = 0;
            ptr->memory = malloc(BLOCK_SIZE);
            memset(ptr->memory, 0, BLOCK_SIZE);
            ptr->next = ptr->prev = NULL;

            if (res->block_list == NULL) {
                res->block_list = res->last_block = ptr;
            } else {
                res->last_block->next = ptr;
                ptr->prev = res->last_block;
                res->last_block = ptr;
            }
        }
        add = new_size - size;
        if(add > BLOCK_SIZE) add = BLOCK_SIZE;
        ptr->occupied = (int)add;
        size += add;

        temp = ptr;
        ptr = ptr->next;
    }

    res->last_block = temp;
    if(res->last_block != NULL) res->last_block->next = NULL;
    else res->block_list = res->last_block;

    while(ptr != NULL){
        temp = ptr->next;

        free(ptr->memory);
        free(ptr);

        ptr = temp;
    }
}
void file_close(struct file *res) {
    if (--res->refs == 0 && res->delete) {
        struct block *ptr = res->block_list;
        struct block *next;
        while(ptr != NULL){
            next = ptr->next;
            free(ptr->memory);
            free(ptr);
            ptr = next;
        }

        if (res->name != NULL) free(res->name);
        if (res == file_list) file_list = res->next;
        if (res->prev != NULL) res->prev->next = res->next;
        if (res->next != NULL) res->next->prev = res->prev;

        free(res);
    }
}

struct filedesc {
	struct file *file;
    size_t pos;


    int is_free;
    int flag;
};

/**
 * An array of file descriptors. When a file descriptor is
 * created, its pointer drops here. When a file descriptor is
 * closed, its place in this array is set to NULL and can be
 * taken by next ufs_open() call.
 */
static struct filedesc **file_descriptors = NULL;
static int file_descriptor_count = 0;
static int file_descriptor_capacity = 0;

int filedesc_find_free() {
    if (file_descriptor_count < file_descriptor_capacity)
        for (int i = 0; i < file_descriptor_capacity; i++)
            if (file_descriptors[i]->is_free) {
                ++file_descriptor_count;
                file_descriptors[i]->is_free = 0;
                return i;
            }

    if (file_descriptors == NULL)
        file_descriptors = malloc(sizeof(struct filedesc *) * (++file_descriptor_capacity));
    else
        file_descriptors = realloc(file_descriptors, sizeof(struct filedesc *) * (++file_descriptor_capacity));

    file_descriptors[file_descriptor_count] = malloc(sizeof(struct filedesc));
    file_descriptors[file_descriptor_count]->file = NULL;
    file_descriptors[file_descriptor_count]->is_free = 0;
    file_descriptors[file_descriptor_count]->flag = 0;
    return file_descriptor_count++;
}
void filedesc_make_free(int fd) {
    if (file_descriptors[fd]->file != NULL) file_close(file_descriptors[fd]->file);
    file_descriptors[fd]->file = NULL;
    file_descriptors[fd]->is_free = 1;
    file_descriptors[fd]->flag = 0;
    file_descriptor_count--;
}

enum ufs_error_code
ufs_errno()
{
	return ufs_error_code;
}

int
ufs_open(const char *filename, int flags)
{
    int fd = filedesc_find_free();
    struct filedesc *fdesc = file_descriptors[fd];
    fdesc->flag = flags;

    if (flags & UFS_CREATE) { // CREATE FILE
        ufs_delete(filename);
        fdesc->file = file_create(filename);
    } else {
        fdesc->file = file_find(filename);
    }
    if (fdesc->file == NULL) { // ERR NO FILE
        filedesc_make_free(fd);
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }
    fdesc->pos = 0;
    return fd;
}

ssize_t
ufs_write(int fd, const char *buf, size_t size)
{
    if(fd < 0 || fd > file_descriptor_capacity || file_descriptors[fd]->is_free) { // ERR NO FILE
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }
    struct filedesc *fdesc = file_descriptors[fd];
    if (ufs_resize(fd, fdesc->pos + size) != 0) return -1;

    struct block *ptr = fdesc->file->block_list;
    size_t _size = 0, add = 0, temp = 0;
    while (_size < fdesc->pos) {
        add = fdesc->pos - _size;
        if(add > BLOCK_SIZE) add = BLOCK_SIZE;
        _size += add;
        if(_size == fdesc->pos) break;
        ptr = ptr->next;
    }

    _size = 0;
    while(_size < size){
        temp = BLOCK_SIZE - add % BLOCK_SIZE;
        if(temp > size - _size) temp = size - _size;

        memcpy(ptr->memory + add % BLOCK_SIZE, buf + _size, temp);
        _size += temp;
        ptr = ptr->next;
        add = 0;
    }
    fdesc->pos += _size;
    return (ssize_t) _size;
}

ssize_t
ufs_read(int fd, char *buf, size_t size)
{
    if(fd < 0 || fd > file_descriptor_capacity || file_descriptors[fd]->is_free) { // ERR NO FILE
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }
    struct filedesc *fdesc = file_descriptors[fd];

    struct block *ptr = fdesc->file->block_list;
    size_t _size = 0, add = 0, temp = 0;
    while (_size < fdesc->pos) {
        add = fdesc->pos - _size;
        if(add > BLOCK_SIZE) add = BLOCK_SIZE;
        _size += add;
        if(_size == fdesc->pos) break;
        ptr = ptr->next;
    }

    _size = 0;
    while(_size < size && ptr != NULL){
        temp = ptr->occupied - add % BLOCK_SIZE;
        if(temp > size - _size) temp = size - _size;
        if(temp == 0) break;

        memcpy(buf + _size, ptr->memory + add % BLOCK_SIZE, temp);
        _size += temp;
        ptr = ptr->next;
        add = 0;
    }
    fdesc->pos += _size;
    return (ssize_t) _size;
}

int
ufs_close(int fd)
{
    if(fd < 0 || fd > file_descriptor_capacity || file_descriptors[fd]->is_free) { // ERR NO FILE
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }
    filedesc_make_free(fd);
    return 0;
}

int
ufs_delete(const char *filename)
{
    struct file *f = file_find(filename);
    if (f == NULL) { // ERR NO FILE
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }

    f->delete = 1;
    file_close(f);
    return 0;
}

int
ufs_resize(int fd, size_t new_size) {
    if(fd < 0 || fd > file_descriptor_capacity || file_descriptors[fd]->is_free) { // ERR NO FILE
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }
    if(new_size > MAX_FILE_SIZE) { // ERR NO MEMORY
        ufs_error_code = UFS_ERR_NO_MEM;
        return -1;
    }

    struct filedesc *fdesc = file_descriptors[fd];
    file_resize(fdesc->file, new_size);
    if(new_size < fdesc->pos) fdesc->pos = new_size;
    return 0;
}

void unit_test_start(){

}
void unit_check(int result, char *str){
    if(!result){
        printf("%s\n", str);
    }
}
void unit_fail_if(int result) {
    if(result) {
        exit(-1);
    }
}
#define unit_msg printf
void unit_test_finish(){

}


static void
test_open(void)
{
    unit_test_start();

    int fd = ufs_open("file", 0);
    unit_check(fd == -1, "error when no such file");
    unit_check(ufs_errno() == UFS_ERR_NO_FILE, "errno is 'no_file'");

    fd = ufs_open("file", UFS_CREATE);
    unit_check(fd != -1, "use 'create' now");
    unit_check(ufs_close(fd) == 0, "close immediately");

    fd = ufs_open("file", 0);
    unit_check(fd != -1, "now open works without 'create'");
    unit_fail_if(ufs_close(fd) != 0);

    fd = ufs_open("file", UFS_CREATE);
    unit_check(fd != -1, "'create' is not an error when file exists");

    int fd2 = ufs_open("file", 0);
    unit_check(fd2 != -1, "open second descriptor");
    unit_check(fd2 != fd, "it is not the same in value");
    unit_check(ufs_close(fd2) == 0, "close the second");

    unit_check(ufs_close(fd) == 0, "and the first");

    unit_check(ufs_delete("file") == 0, "deletion");
    unit_check(ufs_open("file", 0) == -1, "now 'create' is needed again");

    unit_test_finish();
}

static void
test_stress_open(void)
{
    unit_test_start();

    const int count = 1000;
    int fd[count][2];
    char name[16], buf[16];
    unit_msg("open %d read and write descriptors, fill with data", count);
    for (int i = 0; i < count; ++i) {
        int name_len = sprintf(name, "file%d", i) + 1;
        int *in = &fd[i][0], *out = &fd[i][1];
        *in = ufs_open(name, UFS_CREATE);
        *out = ufs_open(name, 0);
        unit_fail_if(*in == -1 || *out == -1);
        ssize_t rc = ufs_write(*out, name, name_len);
        unit_fail_if(rc != name_len);
    }
    unit_msg("read the data back");
    for (int i = 0; i < count; ++i) {
        int name_len = sprintf(name, "file%d", i) + 1;
        int *in = &fd[i][0], *out = &fd[i][1];
        ssize_t rc = ufs_read(*in, buf, sizeof(buf));
        unit_fail_if(rc != name_len);
        unit_fail_if(memcmp(buf, name, rc) != 0);
        unit_fail_if(ufs_close(*in) != 0);
        unit_fail_if(ufs_close(*out) != 0);
        unit_fail_if(ufs_delete(name) != 0);
    }

    unit_test_finish();
}

static void
test_close(void)
{
    unit_test_start();

    unit_check(ufs_close(-1) == -1, "close invalid fd");
    unit_check(ufs_errno() == UFS_ERR_NO_FILE, "errno is set");

    unit_check(ufs_close(0) == -1, "close with seemingly normal fd");
    unit_fail_if(ufs_errno() != UFS_ERR_NO_FILE);

    unit_check(ufs_close(INT_MAX) == -1, "close with huge invalid fd");
    unit_fail_if(ufs_errno() != UFS_ERR_NO_FILE);

    int fd = ufs_open("file", UFS_CREATE);
    unit_fail_if(fd == -1);
    unit_check(ufs_close(fd) == 0, "close normal descriptor");
    unit_check(ufs_close(fd) == -1, "close it second time");
    unit_check(ufs_errno() == UFS_ERR_NO_FILE, "errno is set");

    unit_test_finish();
}

static void
test_io(void)
{
    unit_test_start();

    ssize_t rc = ufs_write(-1, NULL, 0);
    unit_check(rc == -1, "write into invalid fd");
    unit_check(ufs_errno() == UFS_ERR_NO_FILE, "errno is set");
    rc = ufs_write(0, NULL, 0);

    unit_check(rc == -1, "write into seemingly valid fd");
    unit_fail_if(ufs_errno() != UFS_ERR_NO_FILE);

    rc = ufs_read(-1, NULL, 0);
    unit_check(rc == -1, "read from invalid fd");
    unit_check(ufs_errno() == UFS_ERR_NO_FILE, "errno is set");
    rc = ufs_read(0, NULL, 0);

    unit_check(rc == -1, "read from seemingly valid fd");
    unit_fail_if(ufs_errno() != UFS_ERR_NO_FILE);

    int fd1 = ufs_open("file", UFS_CREATE);
    int fd2 = ufs_open("file", 0);
    unit_fail_if(fd1 == -1 || fd2 == -1);

    const char *data = "123";
    int size = strlen(data) + 1;
    unit_check(ufs_write(fd1, data, size) == size, "data is written");

    char buffer[2048];
    unit_check(ufs_read(fd2, buffer, sizeof(buffer)) == size,
               "data is read");
    unit_check(memcmp(data, buffer, size) == 0, "the same data");

    ufs_close(fd1);
    ufs_close(fd2);
    ufs_delete("file");

    unit_test_finish();
}

static void
test_delete(void)
{
    unit_test_start();

    char c1, c2;
    int fd1 = ufs_open("file", UFS_CREATE);
    int fd2 = ufs_open("file", 0);
    int fd3 = ufs_open("file", 0);
    unit_fail_if(fd1 == -1 || fd2 == -1 || fd3 == -1);

    unit_check(ufs_delete("file") == 0,
               "delete when opened descriptors exist");

    int tmp = ufs_open("tmp", UFS_CREATE);
    unit_fail_if(tmp == -1);
    unit_fail_if(ufs_write(tmp, "hhhhh", 5) != 5);
    ufs_close(tmp);

    unit_check(ufs_write(fd2, "a", 1) == 1,
               "write into an fd opened before deletion");
    unit_check(ufs_read(fd3, &c1, 1) == 1,
               "read from another opened fd - it sees the data");
    unit_check(c1 == 'a', "exactly the same data");
    unit_check(ufs_write(fd3, "bc", 2) == 2,
               "write into it and the just read data is not overwritten");

    unit_check(ufs_read(fd1, &c1, 1) == 1, "read from the first one");
    unit_check(ufs_read(fd1, &c2, 1) == 1, "read from the first one again");
    unit_check(c1 == 'a' && c2 == 'b', "it reads data in correct order");

    int fd4 = ufs_open("file", 0);
    unit_check(fd4 == -1, "the existing 'ghost' file is not visible "\
		   "anymore for new opens");
    unit_check(ufs_errno() == UFS_ERR_NO_FILE, "errno is set");

    fd4 = ufs_open("file", UFS_CREATE);
    unit_fail_if(fd4 == -1);
    unit_check(ufs_read(fd4, &c1, 1) == 0,
               "the file is created back, no data");
    unit_check(ufs_read(fd1, &c2, 1) == 1, "but the ghost still lives");
    unit_check(c2 == 'c', "and gives correct data");

    unit_check(ufs_delete("file") == 0, "delete it again");

    unit_fail_if(ufs_close(fd1) != 0);
    unit_fail_if(ufs_close(fd2) != 0);
    unit_fail_if(ufs_close(fd3) != 0);
    unit_fail_if(ufs_close(fd4) != 0);

    unit_fail_if(ufs_delete("tmp") != 0);

    unit_test_finish();
}

static void
test_max_file_size(void)
{
    unit_test_start();

    int fd = ufs_open("file", UFS_CREATE);
    unit_fail_if(fd == -1);

    int buf_size = 1024 * 1024;
    char *buf = (char *) malloc(buf_size);
    for (int i = 0; i < buf_size; ++i)
        buf[i] = 'a' + i % 26;
    for (int i = 0; i < 1024; ++i) {
        ssize_t rc = ufs_write(fd, buf, buf_size);
        unit_fail_if(rc != buf_size);
    }
    unit_check(ufs_write(fd, "a", 1) == -1,
               "can not write over max file size");
    unit_check(ufs_errno() == UFS_ERR_NO_MEM, "errno is set");

    unit_fail_if(ufs_close(fd) != 0);
    fd = ufs_open("file", 0);
    unit_fail_if(fd == -1);
    char *buf2 = (char *) malloc(buf_size);
    for (int i = 0; i < 1014; ++i) {
        ssize_t rc = ufs_read(fd, buf2, buf_size);
        unit_fail_if(rc != buf_size);
        unit_fail_if(memcmp(buf2, buf, buf_size) != 0);
    }
    free(buf2);
    free(buf);
    unit_msg("read works");
    unit_fail_if(ufs_close(fd) == -1);
    unit_fail_if(ufs_delete("file") == -1);

    unit_test_finish();
}

static void
test_rights(void)
{
#ifdef NEED_OPEN_FLAGS
    unit_test_start();

	int fd = ufs_open("file", UFS_CREATE);
	unit_check(fd != -1, "file is opened with 'create' flag only");
	char *buf1 = "hello";
	int buf1_size = strlen(buf1) + 1;
	ssize_t rc = ufs_read(fd, buf1, buf1_size);
	unit_check(rc == 0, "it is allowed to read from it");
	rc = ufs_write(fd, buf1, buf1_size);
	unit_check(rc == buf1_size, "as well as write into it");
	unit_fail_if(ufs_close(fd) != 0);

	fd = ufs_open("file", 0);
	unit_check(fd != -1, "now opened without flags at all");
	char buf2[128];
	unit_check(ufs_read(fd, buf2, sizeof(buf2)) == buf1_size, "can read");
	unit_fail_if(memcmp(buf1, buf2, buf1_size) != 0);
	unit_check(ufs_write(fd, buf1, buf1_size) == buf1_size, "can write");
	unit_fail_if(ufs_close(fd) != 0);

	fd = ufs_open("file", UFS_READ_ONLY);
	unit_check(fd != -1, "opened with 'read only'");
	unit_check(ufs_read(fd, buf2, buf1_size) == buf1_size, "can read");
	unit_fail_if(memcmp(buf1, buf2, buf1_size) != 0);
	unit_check(ufs_write(fd, "bad", 4) == -1, "can not write");
	unit_check(ufs_errno() == UFS_ERR_NO_PERMISSION, "errno is set");
	unit_check(ufs_read(fd, buf2, sizeof(buf2)) == buf1_size,
		   "can again read");
	unit_check(memcmp(buf1, buf2, buf1_size) == 0,
		   "and data was not overwritten");
	unit_fail_if(ufs_close(fd) != 0);

	fd = ufs_open("file", UFS_WRITE_ONLY);
	unit_check(fd != -1, "opened with 'write only");
	unit_check(ufs_read(fd, buf2, sizeof(buf2)) == -1, "can not read");
	unit_check(ufs_errno() == UFS_ERR_NO_PERMISSION, "errno is set");
	char *buf3 = "new data which rewrites previous";
	int buf3_size = strlen(buf3) + 1;
	unit_check(ufs_write(fd, buf3, buf3_size) == buf3_size, "can write");
	unit_fail_if(ufs_close(fd));

	fd = ufs_open("file", UFS_READ_WRITE);
	unit_check(fd != -1, "opened with 'read write");
	unit_check(ufs_read(fd, buf2, sizeof(buf2)) == buf3_size, "can read");
	unit_check(memcmp(buf2, buf3, buf3_size) == 0, "data is correct");
	unit_check(ufs_write(fd, buf1, buf1_size) == buf1_size, "can write");
	unit_fail_if(ufs_close(fd));

	unit_fail_if(ufs_delete("file") != 0);
	unit_test_finish();
#endif
}

static void
test_resize(void)
{
#ifdef NEED_RESIZE
    unit_test_start();

	int fd = ufs_open("file", UFS_CREATE);
	unit_fail_if(fd == -1);
	char buffer[2048];
	memset(buffer, 'a', sizeof(buffer));
	ssize_t rc = ufs_write(fd, buffer, sizeof(buffer));
	unit_fail_if(rc != sizeof(buffer));
	int new_size = 23;
	rc = ufs_resize(fd, new_size);
	unit_check(rc == 0, "shrink to smaller size");

	int fd2 = ufs_open("file2", UFS_CREATE);
	unit_fail_if(fd2 == -1);
	rc = ufs_write(fd2, "123", 3);
	unit_fail_if(rc != 3);
	unit_fail_if(ufs_close(fd2) != 0);
	unit_fail_if(ufs_delete("file2") != 0);

	rc = ufs_write(fd, buffer, sizeof(buffer));
	unit_check(rc == sizeof(buffer),
		   "opened descriptor beyond new border still works");
	unit_fail_if(ufs_close(fd) != 0);
	unit_fail_if(ufs_delete("file") != 0);

	unit_test_finish();
#endif
}

int
main(void)
{
    unit_test_start();

    test_open();
    test_close();
    test_io();
    test_delete();
//    test_stress_open();
    test_max_file_size();
    test_rights();
    test_resize();

    unit_test_finish();
    return 0;
}