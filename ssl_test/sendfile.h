#ifndef __linux__
#ifndef _SENDFILE_H
#define _SENDFILE_H
#include <sys/types.h>

unsigned long long sendfile(int out_fd, int in_fd, off_t *offset, size_t count);

#endif
#endif