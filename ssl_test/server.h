#ifndef _SERVER
#define _SERVER
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <iostream>

#ifndef WIN32
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#else
#define	_WIN32_WINNT 0x600
#include <io.h>
#include <Winsock2.h>
#include <WS2TCPIP.H>
#pragma comment(lib, "ws2_32.lib")
#endif

#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <vector>
#include <string>
#include <sstream>
#include <map>
#include <memory>

#ifdef WIN32
#define SET_NONBLOCK(socket) {DWORD dw = true; ioctlsocket(socket, FIONBIO, &dw);}
typedef int	socklen_t;
#else
#define SET_NONBLOCK(socket) if (fcntl( socket, F_SETFL, fcntl( socket, F_GETFL, 0 ) | O_NONBLOCK ) < 0) printf("error in fcntl errno=%i\n", errno);
#define closesocket(socket)  close(socket)
#define Sleep(a) usleep(a*1000)
#define SOCKET	int
#define INVALID_SOCKET			-1
#define WSAEWOULDBLOCK			EWOULDBLOCK
#define WSAGetLastError()		errno
#define S_OK					0
#define _close		close
#define _open		open
#define _lseek		lseek
#define _read		read
#endif

#ifdef __linux__
#include <sys/epoll.h>
#include <sys/sendfile.h>
#define O_BINARY	0
#else
#include "epoll.h"
#include "sendfile.h"
#endif
#include <sys/stat.h>

/* Make these what you want for cert & key files */
#define CERTF  "./ca-cert.pem"
#define KEYF   "./ca-cert.pem"

using namespace std;
namespace server
{
	enum MESSAGE {
		I_READY_EPOLL,
		I_ACCEPTED,
		I_READ,
		I_ALL_WROTE,
		PLEASE_READ,
		PLEASE_WRITE_BUFFER,
		PLEASE_WRITE_FILE,
		PLEASE_STOP
	};
	enum RETCODES {
		RET_WAIT,
		RET_READY,
		RET_ERROR
	};

	template<class CLIENT>
	class CServerMessages
	{
	public:
		static MESSAGE MessageProc(SOCKET hSocket, MESSAGE message, shared_ptr<vector<unsigned char>> pvBuffer)
		{
			static map<SOCKET, shared_ptr<CLIENT>> mapSocketToClient;

			if (hSocket == INVALID_SOCKET) return message;

			switch (message) {
				case I_ACCEPTED:
					mapSocketToClient[hSocket] = shared_ptr<CLIENT>(new CLIENT);
					return mapSocketToClient[hSocket]->OnAccepted(pvBuffer);
				case I_READ:
					return mapSocketToClient[hSocket]->OnRead(pvBuffer);
				case I_ALL_WROTE:
					return mapSocketToClient[hSocket]->OnWrote(pvBuffer);
				case I_READY_EPOLL: case PLEASE_STOP: case PLEASE_READ: case PLEASE_WRITE_BUFFER: case PLEASE_WRITE_FILE: break;
			}
			mapSocketToClient.erase(hSocket);
			return PLEASE_STOP;
		}
	};
	
	template<class CLIENT, class T = CServerMessages<CLIENT>>
	class CServer 
	{
		class CClient
		{
			int m_nSendFile;
			off_t m_nFilePos;

			SOCKET m_hSocket; //Дескриптор клиентского сокета
			int m_nLastSocketError;
			bool m_bIsSSL;
			vector<unsigned char> m_vRecvBuffer; //В этом буфере клиент будет хранить принятые данные
			vector<unsigned char> m_vSendBuffer; //В этом буфере клиент будет хранить отправляемые данные
		
			//Указатели для взаимодействия с OpenSSL
			SSL_CTX* m_pSSLContext;
			SSL* m_pSSL;

			explicit CClient(const CClient &); //Нам не понадобится конструктор копирования для клиентов
		private:
			struct epoll_event m_ClientEvent; //События сокета клиента
		public:
			const struct epoll_event GetEvent() const {return m_ClientEvent;}
			CClient(const SOCKET hSocket, const bool bIsSSL) : 
				m_nSendFile(-1), m_nFilePos(0), m_hSocket(hSocket), m_nLastSocketError(0), m_bIsSSL(bIsSSL), m_pSSLContext(NULL), m_pSSL(NULL), m_stateCurrent(S_ACCEPTED_TCP), m_pvBuffer(new vector<unsigned char>) 
			{
				if (m_bIsSSL) {
					[](SSL_CTX* pSSLContext){
						if (!pSSLContext)
							ERR_print_errors_fp(stderr);
						if (SSL_CTX_use_certificate_file(pSSLContext, CERTF, SSL_FILETYPE_PEM) <= 0)
							ERR_print_errors_fp(stderr);
						if (SSL_CTX_use_PrivateKey_file(pSSLContext, KEYF, SSL_FILETYPE_PEM) <= 0)
							ERR_print_errors_fp(stderr);
						if (!SSL_CTX_check_private_key(pSSLContext))
							fprintf(stderr,"Private key does not match the certificate public key\n");
					}(m_pSSLContext = SSL_CTX_new (SSLv23_server_method()));
				}
				m_ClientEvent.data.fd = hSocket;
				m_ClientEvent.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLOUT;
			}
			~CClient()
			{
				if(m_hSocket != INVALID_SOCKET) closesocket(m_hSocket);
				if (m_pSSL)	SSL_free (m_pSSL);
				if (m_pSSLContext) SSL_CTX_free (m_pSSLContext);
			}
		private:
			//Перечисляем все возможные состояния клиента. При желании можно добавлять новые.
			enum STATES { 
				S_ACCEPTED_TCP,
				S_READING,
				S_WRITING,
			};
			STATES m_stateCurrent; //Здесь хранится текущее состояние

			//Функция для установки состояния
			void SetState(const STATES state, struct epoll_event *pCurrentEvent) 
			{
				m_stateCurrent = state;

				pCurrentEvent->events = EPOLLERR | EPOLLHUP;
				if (m_bIsSSL) {
					if (m_nLastSocketError == SSL_ERROR_WANT_READ)	pCurrentEvent->events |= EPOLLIN;
					if (m_nLastSocketError == SSL_ERROR_WANT_WRITE)	pCurrentEvent->events |= EPOLLOUT;					
					return;
				}
				if (m_nLastSocketError == WSAEWOULDBLOCK) {
					if (m_stateCurrent == S_READING) pCurrentEvent->events |= EPOLLIN;
					if (m_stateCurrent == S_WRITING) pCurrentEvent->events |= EPOLLOUT;					
					return;
				}
				pCurrentEvent->events |= EPOLLIN | EPOLLOUT;
			}
			shared_ptr<vector<unsigned char>> m_pvBuffer;

			const bool SendMessage(MESSAGE message, struct epoll_event *pCurrentEvent)
			{
				switch(T::MessageProc(m_hSocket,  message, m_pvBuffer)) {
					case PLEASE_READ:
						SetState(S_READING, pCurrentEvent);
						return true;
					case PLEASE_WRITE_BUFFER:
						SetState(S_WRITING, pCurrentEvent);
						m_nSendFile = -1;
						m_vSendBuffer = *m_pvBuffer;
						return true;
					case PLEASE_WRITE_FILE:
						SetState(S_WRITING, pCurrentEvent);
						m_vSendBuffer.clear();
						memcpy(&m_nSendFile, &m_pvBuffer->at(0), m_pvBuffer->size());
						return true;
					case I_READY_EPOLL: case I_ACCEPTED: case I_READ: case I_ALL_WROTE: case PLEASE_STOP: break;
				}
				return false;
			}
		public:
			//Функция для обработки текущего состояния клиента
			const bool Continue(struct epoll_event *pCurrentEvent)
			{
				if (m_hSocket == INVALID_SOCKET) return false;
				switch (m_stateCurrent) {
					case S_ACCEPTED_TCP:
					{
						switch (AcceptSSL()) {
							case RET_READY:
								if (RET_READY != GetSertificate()) return false;
								return SendMessage(I_ACCEPTED, pCurrentEvent);
							case RET_ERROR:	return false;
							default:		return true;
						}
					}
					case S_READING:
					{
						switch (ContinueRead())	{
							case RET_READY:
								*m_pvBuffer = m_vRecvBuffer;
								return SendMessage(I_READ, pCurrentEvent);
							case RET_ERROR: return false;
							default:		return true;
						}
					}
					case S_WRITING:
					{
						if (!m_bIsSSL && (RET_ERROR == SendFileTCP(m_nSendFile, &m_nFilePos)))		return false;
						else if (m_bIsSSL && (RET_ERROR == SendFileSSL(m_nSendFile, &m_nFilePos)))	return false;

						if (IsAllWrote()) return SendMessage(I_ALL_WROTE, pCurrentEvent);
						return true;
					}
					default: return false;
				}
			}
		private:
			int GetLastError(int err) const {return (m_bIsSSL ? SSL_get_error(m_pSSL, err) : WSAGetLastError());}
			const RETCODES AcceptSSL()
			{
				if (!m_bIsSSL)		return RET_READY;
				if (!m_pSSLContext)	return RET_ERROR;

				if (!m_pSSL) {
					if (!(m_pSSL = SSL_new (m_pSSLContext))) return RET_ERROR;
					SSL_set_fd (m_pSSL, m_hSocket);
				}

				const int err = SSL_accept (m_pSSL);
				if (err == 1) return RET_READY;

				return [](const int nErrCode){return (((nErrCode == SSL_ERROR_WANT_READ) || (nErrCode == SSL_ERROR_WANT_WRITE)) ? RET_WAIT : RET_ERROR);}(SSL_get_error(m_pSSL, err));
			}
			const RETCODES GetSertificate()
			{
				cout << "GetSertificate\n";
				if (!m_bIsSSL) return RET_READY;
				if (!m_pSSLContext || !m_pSSL)	return RET_ERROR;
			
				/* Get client's certificate (note: beware of dynamic allocation) - opt */
				cout << "SSL connection using " << SSL_get_cipher (m_pSSL) << "\n";

				return [](X509* client_cert) {
					if (client_cert != NULL) {
						cout << "Client certificate:\n";
						char* str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
						if (!str) return RET_ERROR;
						cout << "\t subject: " << str << "\n"; OPENSSL_free (str);

						str = X509_NAME_oneline (X509_get_issuer_name  (client_cert), 0, 0);
						if (!str) return RET_ERROR;
						cout << "\t issuer: " << str << "\n"; OPENSSL_free (str);
    
						/* We could do all sorts of certificate verification stuff here before
							deallocating the certificate. */    
						X509_free (client_cert);
					} 
					else
						cout << "Client does not have certificate.\n";

					return RET_READY;
				}(SSL_get_peer_certificate (m_pSSL));
			}
			const RETCODES ContinueRead()
			{
				if (m_bIsSSL && (!m_pSSLContext || !m_pSSL)) return RET_ERROR;

				static char szBuffer[4096];
			
				//читаем данные от клиента в буфер
				int err;
				if (m_bIsSSL)
					err = SSL_read (m_pSSL, szBuffer, 4096);
				else {
					errno = 0;
					err = recv(m_hSocket, szBuffer, 4096, 0);
				}
				m_nLastSocketError = GetLastError(err);

				if (err > 0) {
					//Сохраним прочитанные данные в переменной m_vRecvBuffer
					m_vRecvBuffer.resize(m_vRecvBuffer.size()+(size_t)err);
					memcpy(&m_vRecvBuffer[m_vRecvBuffer.size()-err], szBuffer, err);		 
					return RET_READY;
				}
			
				if (!m_bIsSSL) {
					m_nLastSocketError = WSAGetLastError();
					if ((err == 0) || ((m_nLastSocketError != WSAEWOULDBLOCK) && (m_nLastSocketError != S_OK)))
						return RET_ERROR;
				}
				else {
					m_nLastSocketError = SSL_get_error(m_pSSL, err);
					if ((err == 0) || ((m_nLastSocketError != SSL_ERROR_WANT_READ) && (m_nLastSocketError != SSL_ERROR_WANT_WRITE)))
						return RET_ERROR;
				}			
				return RET_WAIT;
			}

			const RETCODES SendFileSSL(const int nFile, off_t *offset)
			{
				if (nFile == -1 || m_vSendBuffer.size()) return ContinueWrite();
				
				if (!m_bIsSSL || !m_pSSLContext || !m_pSSL) return RET_ERROR;
				if (_lseek(nFile, *offset, SEEK_SET) == -1) return RET_ERROR;

				static unsigned char buffer[4096];		
				return [&, this] (const int nRead, const unsigned char *pBuffer) {
					if (nRead == -1) return RET_ERROR;
					if (nRead > 0) {
						*offset += nRead;			
						this->m_vSendBuffer.resize(nRead);
						memcpy(&this->m_vSendBuffer[0], pBuffer, nRead);
					}
					return RET_WAIT;
				}(_read(nFile, buffer, 4096), buffer);
			}
			const RETCODES SendFileTCP(const int nFile, off_t *offset)
			{
				if (nFile == -1 || m_vSendBuffer.size()) return ContinueWrite();
				if ((unsigned long long)-1 == (unsigned long long)sendfile(m_hSocket, nFile, offset, 4096)) return RET_ERROR;
				
				m_nLastSocketError = WSAEWOULDBLOCK;
				return RET_WAIT;
			}
			const bool IsAllWrote() const
			{
				if (m_vSendBuffer.size())	return false;
				if (m_nSendFile == -1)		return true;

				struct stat stat_buf;
				if (fstat(m_nSendFile, &stat_buf) == -1) return true;				
				if (stat_buf.st_size == m_nFilePos)	return true;

				return false;
			}
			const RETCODES ContinueWrite()
			{
				if (m_bIsSSL && (!m_pSSLContext || !m_pSSL)) return RET_ERROR;

				int err;
				if (m_bIsSSL)
					err = SSL_write (m_pSSL, &m_vSendBuffer[0], m_vSendBuffer.size());
				else {
					errno = 0;
					err = send(m_hSocket, (const char*)&m_vSendBuffer[0], m_vSendBuffer.size(), 0);
				}
				m_nLastSocketError = GetLastError(err);

				if (err > 0) {
					//Если удалось послать все данные, то переходим к следующему состоянию
					if ((size_t)err == m_vSendBuffer.size()) {
						m_vSendBuffer.clear();
						return RET_READY;
					}
					//Если отослали не все данные, то оставим в буфере только то, что еще не послано
					vector<unsigned char> vTemp(m_vSendBuffer.size()-err);
					memcpy(&vTemp[0], &m_vSendBuffer[err], m_vSendBuffer.size()-err);
					m_vSendBuffer = vTemp;
					return RET_WAIT;
				}
				return [this, err]() -> RETCODES {
					if (!this->m_bIsSSL && ((err == 0) || ((this->m_nLastSocketError != WSAEWOULDBLOCK) && (this->m_nLastSocketError != S_OK)))) return RET_ERROR;
					if (this->m_bIsSSL && ((err == 0) || ((this->m_nLastSocketError != SSL_ERROR_WANT_READ) && (this->m_nLastSocketError != SSL_ERROR_WANT_WRITE)))) return RET_ERROR;				
					return RET_WAIT;
				}();
			}	 
		};
		map<SOCKET, shared_ptr<CClient> > m_mapClients; //Здесь сервер будет хранить всех клиентов
		struct epoll_event m_ListenEventTCP, m_ListenEventSSL; //События слушающего сокета
		vector<struct epoll_event> m_events; //События клиентских сокетов

		explicit CServer(const CServer &); //Нам не понадобится конструктор копирования для сервера
	public:
		CServer(const uint16_t nPortTCP, const uint16_t nPortSSL)
		{
#ifndef WIN32
			struct sigaction sa;			
			memset(&sa, 0, sizeof(sa));		
			sa.sa_handler = SIG_IGN;		
			sigaction(SIGPIPE, &sa, NULL);
#else
			WSADATA wsaData;
			if ( WSAStartup( MAKEWORD( 2, 2 ), &wsaData ) != 0 ) {
				cout << "Could not to find usable WinSock in WSAStartup\n";
				return;
			}
#endif
			SSL_load_error_strings();
			SSLeay_add_ssl_algorithms();
			
			/* ----------------------------------------------- */
			/* Prepare TCP socket for receiving connections */

			[this, nPortTCP, nPortSSL](const int nEpoll) {
				if (nEpoll == -1) {
					cout << "error: epoll_create";
					return;
				}

				this->InitListenSocket(nEpoll, nPortTCP, m_ListenEventTCP, socket (AF_INET6, SOCK_STREAM, 0));
				this->InitListenSocket(nEpoll, nPortSSL, m_ListenEventSSL, socket (AF_INET6, SOCK_STREAM, 0));

				while(PLEASE_STOP != T::MessageProc(INVALID_SOCKET, I_READY_EPOLL, shared_ptr<vector<unsigned char>>(new vector<unsigned char>))) {
					m_events.resize(m_mapClients.size()+2);
					this->Callback(nEpoll, epoll_wait(nEpoll, &m_events[0], m_events.size(), 5000));
				}
			}(epoll_create (1));
		}
	private:
		void InitListenSocket(const int nEpoll, const uint16_t nPort, struct epoll_event &eventListen, const SOCKET listen_sd)
		{
			SET_NONBLOCK(listen_sd);
  
			[listen_sd](const char on){
				setsockopt(listen_sd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
				setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
			}(1);

			struct sockaddr_in6 sa_serv;
			memset (&sa_serv, '\0', sizeof(sa_serv));
			sa_serv.sin6_family     = AF_INET6;
			sa_serv.sin6_addr		= in6addr_any;
			sa_serv.sin6_port		= htons (nPort);          /* Server Port number */
  
			if (-1 == ::bind(listen_sd, (struct sockaddr*) &sa_serv, sizeof (sa_serv))) {
				cout << "bind error = " << errno << "\n";
				return;
			}
			/* Receive a TCP connection. */
			listen (listen_sd, SOMAXCONN);

			eventListen.data.fd = listen_sd;
			eventListen.events = EPOLLIN | EPOLLET;
			epoll_ctl (nEpoll, EPOLL_CTL_ADD, listen_sd, &eventListen);
		}
		void AcceptClient(const int nEpoll, const SOCKET hSocketIn, const bool bIsSSL)
		{
			struct sockaddr_in6 sa_cli;  
			socklen_t client_len = sizeof(sa_cli);
			
			[this, bIsSSL, nEpoll](const SOCKET sd) {
				if (sd != INVALID_SOCKET) {
					//Добавляем нового клиента в класс сервера
					cout << "Client Accepted\n";
					m_mapClients[sd] = shared_ptr<CClient>(new CClient(sd, bIsSSL));
				
					auto it = m_mapClients.find(sd);
					if (it == m_mapClients.end()) return;
						
					//Добавляем нового клиента в epoll
					[this, it, nEpoll](struct epoll_event ev){epoll_ctl (nEpoll, EPOLL_CTL_ADD, it->first, &ev);}(it->second->GetEvent());
				}					
			}(accept (hSocketIn, (struct sockaddr*) &sa_cli, (socklen_t *)&client_len));
		}
		void Callback(const int nEpoll, const int nCount)
		{
			static time_t tmLast = time(NULL);
			if (time(NULL) - tmLast > 10)
			{
				tmLast = time(NULL);
				cout << "ClientsCount=" << m_mapClients.size() << "\n";
			}
			for (int i = 0; i < nCount; i++) {
				SOCKET hSocketIn = m_events[i].data.fd;
				if (m_ListenEventTCP.data.fd == (int)hSocketIn)	{
					if (m_events[i].events & EPOLLIN)
						AcceptClient(nEpoll, hSocketIn, false);
					continue;
				}
				if (m_ListenEventSSL.data.fd == (int)hSocketIn)	{
					if (m_events[i].events & EPOLLIN)
						AcceptClient(nEpoll, hSocketIn, true);
					continue;
				}
				
				auto it = m_mapClients.find(hSocketIn); //Находим клиента по сокету
				if (it == m_mapClients.end())
					continue;

				if (!it->second->Continue(&m_events[i])) {
					//Если клиент вернул false, то удаляем клиента из epoll и из класса сервера
					epoll_ctl (nEpoll, EPOLL_CTL_DEL, it->first, NULL);
					m_mapClients.erase(it);					
					cout << "Delete Client, ClientsCount=" << m_mapClients.size() << "\n";
				}
			}
		}
	};
}

#endif
