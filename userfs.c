#include "userfs.h"
#include <stddef.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>

enum {
    BLOCK_SIZE = 512,
    MAX_FILE_SIZE = 1024 * 1024 * 100,
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
    size_t size;

	/* PUT HERE OTHER MEMBERS */
};

/** List of all files. */
static struct file *file_list = NULL;

struct file *file_find(const char *filename) {
    size_t name_size = strlen(filename);
    struct file *ptr = file_list;
    while (ptr != NULL) {
        if (!ptr->delete && strcmp(filename, ptr->name) == 0) {
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
    res->size = 0;
    res->name = strdup(filename);

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
    if(fd < 0 || fd >= file_descriptor_capacity || file_descriptors[fd]->is_free) { // ERR NO FILE
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }
    struct filedesc *fdesc = file_descriptors[fd];

    if (fdesc->file->size < fdesc->pos) fdesc->pos = fdesc->file->size;
    if (fdesc->file->size < fdesc->pos + size && ufs_resize(fd, fdesc->pos + size) != 0) return -1;
    if (fdesc->flag & UFS_READ_ONLY){
        ufs_error_code = UFS_ERR_NO_PERMISSION;
        return -1;
    }

    struct block *ptr = fdesc->file->block_list;
    size_t _size = 0, add = 0, temp = 0;
    while (_size < fdesc->pos) {
        add = fdesc->pos - _size;
        if(add > BLOCK_SIZE) add = BLOCK_SIZE;
        _size += add;
        if(add == BLOCK_SIZE) ptr = ptr->next;
        if(_size == fdesc->pos) break;
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
    if(fd < 0 || fd >= file_descriptor_capacity || file_descriptors[fd]->is_free) { // ERR NO FILE
        ufs_error_code = UFS_ERR_NO_FILE;
        return -1;
    }
    struct filedesc *fdesc = file_descriptors[fd];

    if (fdesc->file->size < fdesc->pos) fdesc->pos = fdesc->file->size;
    if (fdesc->flag & UFS_WRITE_ONLY){
        ufs_error_code = UFS_ERR_NO_PERMISSION;
        return -1;
    }

    struct block *ptr = fdesc->file->block_list;
    size_t _size = 0, add = 0, temp = 0;
    while (_size < fdesc->pos) {
        add = fdesc->pos - _size;
        if(add > BLOCK_SIZE) add = BLOCK_SIZE;
        _size += add;
        if(add == BLOCK_SIZE) ptr = ptr->next;
        if(_size == fdesc->pos) break;
    }

    _size = 0;
    while(_size < size && ptr != NULL) {
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
    if(fd < 0 || fd >= file_descriptor_capacity || file_descriptors[fd]->is_free) { // ERR NO FILE
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
    if(fd < 0 || fd >= file_descriptor_capacity || file_descriptors[fd]->is_free) { // ERR NO FILE
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
    fdesc->file->size = new_size;
    return 0;
}
