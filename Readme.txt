������������������ ������ � �������������� ��������. ����� 4
��� ������ ���������� ��� ����������:
���������� ����c������������� ������ � ���������� ssl
������������������ https ������ � �������������� �������� 
������������������ https ������ � �������������� ��������. ����� 2
������������������ https ������ � �������������� ��������. ����� 3

� ����� ������� � �������� ���������� ������� �������� ������������� ������������������� ������� �� ������������� �������.
�� ���� ���������� �������, ������ �������� � ��������� ��������� ������ �� ssl ���������. � ���� ������ � ����� ���������� � ������
��������� �������� �������������� tcp ��������� � ����� ������ ���������� �������� ����������� ����.
�� ������� ������� �������� �� ������������ � ���������� �������.

1. � �������� ������� ���������� �� ������� printf � ������ std::cout.
2. ����� ���� �������� ���, ��� std::memcpy � std::copy ��� ����������� ���� � �� ��. 
��� memcpy �������, ������� ���� ���������� ������������ ��.
3. � ������� ��� ������ ������ � ���� ���������� �������� �� GitHub, ���� ������ ��� Windows � ���, �� ��� ������, ������.
4. ��� �������, ��� �������
			const char on = 1;
			setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) );
������� �������� ������ "Address already in use" ��� ��������� ����������� ������� - ������� ���������. �� �������.
5. ���, ��� �������, ��� ������ ������ ������ ����� ��������� �� ������ ������, ������� �����: � ���� ��������� ����� CClient � 
��������� ������ ������ CServer!

����:
CClient
{
***
};
CServer
{
***
};

�����:
CServer
{
	CClient
	{
	***
	};
***
};

������, ���� ������ ������ �����������, �� � ���� �� ������ ���������� ����� �� ������������� ������ CClient: ��� ��������� �����, ���������������
������������� ��� �������������� � ������� CServer.

6. � ��� �� ��� ������, ������� main() - �������, ����������� ������������� �� ��. � �++ ��� ������. �� ����������� ���� ����� �� ����� � ���������.
�� � ����� "��������" ��� �������� �������, ������� � ��� ����������� ���-���� ������� - ������� ���� serv.cpp ��������� �������:

#include "server.h"

const server::CServer s(8085, 1111);

int main() {return 0;}


������ � �������.
���������� � ������ ��������� ������������� tcp ����������.
������������� � ����������� ���������� � �������� ������ ����������� �� ������ ����� ������� ������, ��� ����� ������� - ��� �������� �����������
������� � �������� ����������, ��� ��� ������ ���������� ������.

������
struct epoll_event m_ListenEvent;
����� � ������ �������
struct epoll_event m_ListenEventTCP, m_ListenEventSSL;

� ������������ ������� ������� ������ ������ � ��� ��� �������, ������� �� �������� �������� ����������� ������� � ������ ������ � TCP ���������:
		CServer(const int nPortTCP, const int nPortSSL)
		{
#ifndef WIN32
			struct sigaction sa;			
			memset(&sa, 0, sizeof(sa));		
			sa.sa_handler = SIG_IGN;		
			sigaction(SIGPIPE, &sa, NULL);
#else
			WSADATA wsaData;
			if ( WSAStartup( MAKEWORD( 2, 2 ), &wsaData ) != 0 )
			{
				cout << "Could not to find usable WinSock in WSAStartup\n";
				return;
			}
#endif

������� ��������� ������� ��� ��������� ��������� ������� � ��� ���������� ������ �������:
	private:
		void InitListenSocket(const int nPort, struct epoll_event &eventListen)
		{
			SOCKET listen_sd = socket (AF_INET, SOCK_STREAM, 0);
			SET_NONBLOCK(listen_sd);
  
			const char on = 1;
			setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) );

			struct sockaddr_in sa_serv;
			memset (&sa_serv, '\0', sizeof(sa_serv));
			sa_serv.sin_family      = AF_INET;
			sa_serv.sin_addr.s_addr = INADDR_ANY;
			sa_serv.sin_port        = htons (nPort);          /* Server Port number */
  
			int err = ::bind(listen_sd, (struct sockaddr*) &sa_serv, sizeof (sa_serv));
	     
			if (err == -1)
			{
				cout << "bind error = " << errno << "\n";
				return;
			}
			/* Receive a TCP connection. */
			
			err = listen (listen_sd, SOMAXCONN);

			eventListen.data.fd = listen_sd;
			eventListen.events = EPOLLIN | EPOLLET;
			epoll_ctl (m_epoll, EPOLL_CTL_ADD, listen_sd, &eventListen);
		}
		void AcceptClient(const SOCKET hSocketIn, const bool bIsSSL)
		{
			cout << "AcceptClient";
			struct sockaddr_in sa_cli;  
			size_t client_len = sizeof(sa_cli);
#ifdef WIN32
			const SOCKET sd = accept (hSocketIn, (struct sockaddr*) &sa_cli, (int *)&client_len);
#else
			const SOCKET sd = accept (hSocketIn, (struct sockaddr*) &sa_cli, (socklen_t *)&client_len);
#endif  
			if (sd != INVALID_SOCKET)
			{
				cout << "Accepted\n";
				//��������� ������ ������� � ����� �������
				m_mapClients[sd] = shared_ptr<CClient>(new CClient(sd, bIsSSL));
						
				auto it = m_mapClients.find(sd);
				if (it == m_mapClients.end())
					return;
						
				//��������� ������ ������� � epoll
				struct epoll_event ev = it->second->GetEvent();
				epoll_ctl (m_epoll, EPOLL_CTL_ADD, it->first, &ev);
			}					
		}

������ � ������� ������� ���������� m_bIsSSL, ������� ����� ������������ � ������������, � ����� ������� callback ������� ���,
����� ��� ����� �������� � TCP ������������:
������
		const RETCODES AcceptSSL()
		{
			if (!m_pSSLContext) //��� ������ ������������ ������ ��� SSL
				return RET_ERROR;
����� �����:
			const RETCODES AcceptSSL()
			{
				cout << "AcceptSSL\n";
				if (!m_bIsSSL) return RET_READY;

				if (!m_pSSLContext)
					return RET_ERROR;

��� �����, ����� ������: TCP ������� accept �� ������� ������� �������������� ������������ ��� ����, ����� ������ ��������� � �������� ������.
������� ������������ ��� TCP �� �����, ������� ������ ��������������� ������� ����� ������ ��������� ���:
			const RETCODES GetSertificate()
			{
				cout << "GetSertificate\n";
				if (!m_bIsSSL) return RET_READY;

� �������, �������� ������ �� ������� ContinueRead() ����� ������
			unsigned char szBuffer[4096];
			
			const int err = SSL_read (m_pSSL, szBuffer, 4096); //������ ������ �� ������� � �����
�������� ���:

				static char szBuffer[4096];
			
				//������ ������ �� ������� � �����
				int err;
				if (m_bIsSSL)
					err = SSL_read (m_pSSL, szBuffer, 4096);
				else
				{
					errno = 0;
					err = recv(m_hSocket, szBuffer, 4096, 0);
				}
				m_nLastSocketError = GetLastError(err);

� ���� �� ������� ����� ������ �������� ��� ��������� ������ ��� TCP ����������. ��� � � ������ SSL, ������� �����
���� ������� ������ ��������� ������ ������������� ��� ������� ��������. �� ��� ��� � ��� ������������� ������,
�� ������ WSAEWOULDBLOCK � Windows � EWOULDBLOCK � Linux ��������, ��� ��� ���������, ������ ����� ��� ���������.
������� ����� �������:
#ifndef _WIN32
#define S_OK				0
#define WSAEWOULDBLOCK			EWOULDBLOCK
#define WSAGetLastError()		errno
#endif

� ����� ��� � ������� ContinueRead:
				m_nLastSocketError = GetLastError(err);
				if (!m_bIsSSL)
				{
					if ((err == 0) || ((m_nLastSocketError != WSAEWOULDBLOCK) && (m_nLastSocketError != S_OK)))
						return RET_ERROR;
				}
				else
				{
					if ((err == 0) || ((m_nLastSocketError != SSL_ERROR_WANT_READ) && (m_nLastSocketError != SSL_ERROR_WANT_WRITE)))
						return RET_ERROR;
				}

� ������� CClient::GetLastError �� ��������� ���
		private:
			int GetLastError(int err) const
			{
				if (m_bIsSSL)
					return SSL_get_error(m_pSSL, err);
				else
					return WSAGetLastError();
			}

���������� ����������� ������� �������� ������� �������� ��������� ContinueWrite � ��� ������������ ������������������ ������ ����� ��� ������ tcp � ssl
���������� �� ��������, ����� ������ �� ��������� �������.
������� ��� ������ ������� ��� ������ �������� �������� �����.
� �������� ������ � ���� ���������� ��� ���� �� �������, ��� � Linux ��� �������� ����� ���� ����� ������� ������ ��� � ������ ��������: ������� sendfile.
����� ��� ��� �������������, � ��������� ��������� � sendfile ��� ��, ��� �� ��������� � epoll: �������� �������� ���� ������� ��� ���� ������ ����� Linux.

�������� ������� sendfile 
1. �������� ������ ����� "sendfile.h", "sendfile.cpp" � ������� �� � ������ Visual Studio.
2. � sendfile.h �������� ����� ���:
#ifndef __linux__
#ifndef _SENDFILE_H
#define _SENDFILE_H
#include <sys/types.h>

unsigned long long sendfile(int out_fd, int in_fd, off_t *offset, size_t count);

#endif
#endif
3. � sendfile.cpp �������� �����:

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

4. ������� � ����� ������� ����������� ��������� ���, ����� � Linux �������������� ����������� �������, � � ��������� �������� - ����.
����� �����, ������� ��������� ��� ������ � ������� � ��������� ���� � �����, ������� ����� �������� �������:
#ifdef __linux__
#include <sys/epoll.h>
#include <sys/sendfile.h>
#define O_BINARY	0
#else
#include "epoll.h"
#include "sendfile.h"
#endif
#include <sys/stat.h>
#define SEND_FILE "./wwwroot/festooningloops.jpg"


5. ������� � ����� ������� �������� ���������� � ������� �������
	class CClient
	{
		int m_nSendFile;
		off_t m_nFilePos;
		unsigned long long m_nFileSize;

6. �������� ������� InitRead()
			const RETCODES InitRead()
			{
				if (m_bIsSSL && (!m_pSSLContext || !m_pSSL))
					return RET_ERROR;

				m_nSendFile = _open(SEND_FILE, O_RDONLY|O_BINARY);
				if (m_nSendFile == -1)
					return RET_ERROR;
			
				struct stat stat_buf;
				if (fstat(m_nSendFile, &stat_buf) == -1)
					return RET_ERROR;

				m_nFileSize = stat_buf.st_size;

				//��������� � ������ ������ http ���������
 				std::ostringstream strStream;
				strStream << 
						"HTTP/1.1 200 OK\r\n"
						<< "Content-Type: image/jpeg\r\n"
						<< "Content-Length: " << m_nFileSize << "\r\n" <<
						"\r\n";

				//���������� ���������
				m_vSendBuffer.resize(strStream.str().length());
				memcpy(&m_vSendBuffer[0], strStream.str().c_str(), strStream.str().length());

				return RET_READY;
			}
7. ��������� ������� ��� ������� ����� �� ���������� tcp � ssl:
			const RETCODES SendFileSSL(const int nFile, off_t *offset)
			{
				if (nFile == -1 || m_vSendBuffer.size())
					return ContinueWrite();

				if (!m_bIsSSL || !m_pSSLContext || !m_pSSL)
					return RET_ERROR;

				static unsigned char buffer[4096];

				off_t lPos = _lseek(nFile, *offset, SEEK_SET);
				if (lPos == -1)
					return RET_ERROR;

				const int nReaded = _read(nFile, buffer, 4096);
	
				if (nReaded == -1)
					return RET_ERROR;
			
				if (nReaded > 0)
				{
					*offset += nReaded;
				
					m_vSendBuffer.resize(nReaded);
					memcpy(&m_vSendBuffer[0], buffer, nReaded);
				}

				return RET_WAIT;
			}
			const RETCODES SendFileTCP(const int nFile, off_t *offset)
			{
				if (nFile == -1 || m_vSendBuffer.size())
					return ContinueWrite();

				const unsigned long long nSended = sendfile(m_hSocket, nFile, offset, 4096);
				if (nSended == (unsigned long long)-1)
					return RET_ERROR;

				m_nLastSocketError = WSAEWOULDBLOCK;
				return RET_WAIT;
			}
			const bool IsAllWrited() const
			{
				if (m_nSendFile == -1 && m_vSendBuffer.size())
					return true;

				if (m_nFileSize == (unsigned long long)m_nFilePos)
					return true;

				return false;
			}
8. �������� ������ callback ������� �������:
					case S_WRITING:
					{
						if (!m_bIsSSL && (SendFileTCP(m_nSendFile, &m_nFilePos) == RET_ERROR))
							return false;
						else if (m_bIsSSL && (SendFileSSL(m_nSendFile, &m_nFilePos) == RET_ERROR))
							return false;

						if (IsAllWrited())
							SetState(S_ALL_WRITED, pCurrentEvent);
						return true;
					}
��� ������ �����!
������ �� ����� ���������� �� ������ �����, �� � �����.
�������� ���-�� �������, ��� � ������ ������� ���������� ���������� "m_nLastSocketError". ���� � ���, ��� � ���������� ������� �������
�� ������ ����� �� ������� ����� �������, ���������� m_nLastSocketError ������� ��� �������������� ������� CClient::SetState ���, ����� ������� epoll
�� ������� ����� ������ ��� �������, ������� ����� � ������ ������.
			void SetState(const STATES state, struct epoll_event *pCurrentEvent) 
			{
				m_stateCurrent = state;

				pCurrentEvent->events = EPOLLERR | EPOLLHUP;
				if (m_bIsSSL)
				{
					if (m_nLastSocketError == SSL_ERROR_WANT_READ)
						pCurrentEvent->events |= EPOLLIN;
					if (m_nLastSocketError == SSL_ERROR_WANT_WRITE)
						pCurrentEvent->events |= EPOLLOUT;
					return;
				}

				if (m_nLastSocketError == WSAEWOULDBLOCK)
				{
					if (m_stateCurrent == S_READING)
						pCurrentEvent->events |= EPOLLIN;
					if (m_stateCurrent == S_WRITING)
						pCurrentEvent->events |= EPOLLOUT;
					return;
				}

				pCurrentEvent->events |= EPOLLIN | EPOLLOUT;
			}


��� ����������� Visual Studio 2012, �������� ���� ssl_test.sln
��� ���������� � Linux ����� epoll.h, epoll.cpp, sendfile.h � sendfile.cpp �� �����, ����� ��� �������� ���������� ����������� � ���� ���������� �����: serv.cpp, server.h, ca-cert.pem, �������
���������� wwwroot � ����������� ���� ���� ./wwwroot/festooningloops.jpg, ����� � ��������� ������ �������: �g++ -std=c++0x -L/usr/lib -lssl -lcrypto serv.cpp�
��� �����-�� ����� ������ �������������� �����������, �������� ��� ����� -Wall.

