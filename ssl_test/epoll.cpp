#ifndef __linux__
#include "epoll.h"
#include <map>
#ifndef WIN32
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#else
#include <io.h>
#include <Winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#endif

std::map<int, epoll_event> g_mapSockets;

int epoll_create(int)
{
	return 1;
}

int epoll_ctl(int, int op, int fd, struct epoll_event *event)
{
	switch(op)
	{
		case EPOLL_CTL_ADD:
		case EPOLL_CTL_MOD:
			g_mapSockets[fd] = *event;
			return 0;
		case EPOLL_CTL_DEL:
			if (g_mapSockets.find(fd) == g_mapSockets.end()) 
				return -1;

			g_mapSockets.erase(fd);
			return 0;
	}
	return 0;
}

int epoll_wait(int, struct epoll_event *events, int maxevents, int timeout)
{
	if ((!events) || (!maxevents))
		return -1;

	//Создаем и обнуляем структуры для функции select
	fd_set readfds, writefds, exceptfds;
	
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);
	
	//Заполняем структуры сокетами
	int nFDS = 0;
	for (auto it=g_mapSockets.begin(); it != g_mapSockets.end(); ++it)
	{
		if (it->first == -1)
			continue;
		
		if (it->first > nFDS)
			nFDS = it->first;

		FD_SET(it->first, &readfds);
		FD_SET(it->first, &writefds);
		FD_SET(it->first, &exceptfds);
	}

	//Задаем интервал ожидания
	struct timeval tv;
	tv.tv_sec = timeout/1000;
	tv.tv_usec = timeout - tv.tv_sec*1000;

	//Ждем событий
	nFDS++;
	select(nFDS, &readfds, &writefds, &exceptfds, &tv);

	//Заполняем структуру для отправки программе так, как будто она вызвала epoll
	int nRetEvents = 0;
	for (auto it=g_mapSockets.begin(); (it != g_mapSockets.end() && nRetEvents < maxevents); ++it)
	{
		if (it->first == -1)
			continue;
		if (!FD_ISSET(it->first, &readfds) && !FD_ISSET(it->first, &writefds) && !FD_ISSET(it->first, &exceptfds))
			continue;

		memcpy(&events[nRetEvents].data, &it->second.data, sizeof(epoll_data));
		
		if (FD_ISSET(it->first, &readfds))
			events[nRetEvents].events |= EPOLLIN;
		if (FD_ISSET(it->first, &writefds))
			events[nRetEvents].events |= EPOLLOUT;
		if (FD_ISSET(it->first, &exceptfds))
			events[nRetEvents].events |= EPOLLERR;

		nRetEvents++;
	}

	return nRetEvents;
}
#endif
