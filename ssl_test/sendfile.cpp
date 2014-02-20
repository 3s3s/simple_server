#ifndef __linux__
#include "sendfile.h"
#include <fcntl.h>
#ifndef WIN32
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define WSAGetLastError()		errno
#define SOCKET_ERROR			-1
#define WSAEWOULDBLOCK			EWOULDBLOCK
#define _close		close
#define _open		open
#define _lseek		lseek
#define _read		read
#else
#include <io.h>
#include <Winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#endif

unsigned long long sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
	static unsigned char buffer[4096];

	if (count > 4096)
		count = 4096;

	off_t lPos = _lseek(in_fd, *offset, SEEK_SET);
	if (lPos == -1)
		return -1;

	const int nReaded = _read(in_fd, buffer, count);
	
	if (nReaded == 0)
		return nReaded;
	if (nReaded == -1)
		return -1;

	*offset += nReaded;

	errno = 0;
	const int nSended = send(out_fd, (const char *)buffer, nReaded, 0);

	if (nSended != SOCKET_ERROR)
		return nSended;

	if (WSAGetLastError() != WSAEWOULDBLOCK)
		return -1;

	return 0;
}
#endif