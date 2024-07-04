# UserFS: In-Memory File System Implementation
## Overview
This project involves implementing an in-memory file system called UserFS. Unlike traditional file systems, UserFS operates entirely in main memory, using dynamically allocated structures similar to those found in FAT (File Allocation Table) systems. This README provides an overview of the system, its components, and usage instructions.

## Components
### 1. File System Interface:

The file system provides functions similar to libc for file management:
* `int ufs_open(const char *filename, int flags);`
* `ssize_t ufs_write(int fd, const char *buf, size_t size);`
* `ssize_t ufs_read(int fd, char *buf, size_t size);`
* `int ufs_close(int fd);`
* `int ufs_delete(const char *filename);`
### 2. File and Block Structures:

* `File Structure`: Each file in UserFS consists of a linked list of blocks. Blocks are dynamically allocated chunks of fixed size.
* `Block Structure`: Blocks store data and pointers to the next block in the file. If a file exceeds the capacity of a single block, additional blocks are allocated and linked.
### 3. Operations:

* `ufs_open`: Creates a new file or opens an existing one. Returns a file descriptor (fd).
* `ufs_write`: Appends data to a file. Handles block allocation and linking as needed when the file grows.
* `ufs_read`: Reads data from a file sequentially, moving to the next block when necessary.
* `ufs_close`: Closes a file descriptor and frees associated resources.
* `ufs_delete`: Deletes a file from the file system.
## Implementation Details
* `File Growth`: When writing data (ufs_write), if the current block is full, additional blocks are allocated and linked to accommodate new data.

* `File Descriptor`: Each open file is associated with a file descriptor (fd) which tracks the current position in the file and other relevant metadata.

* `No Disk Storage`: UserFS operates entirely in main memory, making it suitable for applications where rapid access and simplicity are prioritized over persistence.

## Example Usage

```c++
#include "userfs.h"

int main() {
int fd = ufs_open("example.txt", UFS_CREATE); // Create or open 'example.txt'

    const char *data1 = "Hello, ";
    ufs_write(fd, data1, strlen(data1)); // Write data1 to the file
    
    char buf[1024];
    memset(buf, 0, sizeof(buf));
    ufs_write(fd, buf, sizeof(buf)); // Write 1024 zeros to the file
    
    ufs_close(fd); // Close the file
    
    return 0;
}
```

## Conclusion
UserFS provides a basic yet functional in-memory file system implementation suitable for educational purposes or applications where a lightweight file system is required. The provided API closely resembles standard libc functions, making integration straightforward for C applications.

For detailed function descriptions and implementation specifics, refer to `userfs.h` and `userfs.c`.