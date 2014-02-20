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
#include <io.h>
#include <Winsock2.h>
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
#define SET_NONBLOCK(socket)	\
	if (true)					\
	{							\
		DWORD dw = true;			\
		ioctlsocket(socket, FIONBIO, &dw);	\
	}
#else
#define SET_NONBLOCK(socket)	\
	if (fcntl( socket, F_SETFL, fcntl( socket, F_GETFL, 0 ) | O_NONBLOCK ) < 0)	\
		printf("error in fcntl errno=%i\n", errno);
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
#define SEND_FILE "./wwwroot/festooningloops.jpg"

/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */
#define CERTF  HOME "ca-cert.pem"
#define KEYF  HOME  "ca-cert.pem"

using namespace std;
namespace server
{

	class CServer
	{
		class CClient
		{
			int m_nSendFile;
			off_t m_nFilePos;
			unsigned long long m_nFileSize;

			SOCKET m_hSocket; //Дескриптор клиентского сокета
			int m_nLastSocketError;
			bool m_bIsSSL;
			vector<unsigned char> m_vRecvBuffer; //В этом буфере клиент будет хранить принятые данные
			vector<unsigned char> m_vSendBuffer; //В этом буфере клиент будет хранить отправляемые данные
		
			//Указатели для взаимодействия с OpenSSL
			SSL_CTX* m_pSSLContext;
			SSL* m_pSSL;

			explicit CClient(const CClient &) {} //Нам не понадобится конструктор копирования для клиентов
		private:
			//События сокета клиента
			struct epoll_event m_ClientEvent;
		public:
			const struct epoll_event GetEvent() const {return m_ClientEvent;}
			CClient(const SOCKET hSocket, const bool bIsSSL) : 
				m_nSendFile(-1), m_nFilePos(0), m_nFileSize(0), m_hSocket(hSocket), m_nLastSocketError(0), m_bIsSSL(bIsSSL), m_pSSLContext(NULL), m_pSSL(NULL), m_stateCurrent(S_ACCEPTED_TCP)
				
			{
				if (m_bIsSSL)
				{
	#ifdef WIN32
					const SSL_METHOD *meth = SSLv23_server_method();
	#else
	#if __GNUC__ <= 4 && __GNUC_MINOR__ <= 4
					SSL_METHOD *meth = SSLv23_server_method();
	#else
					const SSL_METHOD *meth = SSLv23_server_method();
	#endif
	#endif
					m_pSSLContext = SSL_CTX_new (meth);
					if (!m_pSSLContext)
						ERR_print_errors_fp(stderr);
		
					if (SSL_CTX_use_certificate_file(m_pSSLContext, CERTF, SSL_FILETYPE_PEM) <= 0)
						ERR_print_errors_fp(stderr);
					if (SSL_CTX_use_PrivateKey_file(m_pSSLContext, KEYF, SSL_FILETYPE_PEM) <= 0)
						ERR_print_errors_fp(stderr);

					if (!SSL_CTX_check_private_key(m_pSSLContext))
						fprintf(stderr,"Private key does not match the certificate public key\n");
				}

				m_ClientEvent.data.fd = hSocket;
				m_ClientEvent.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLOUT;
			}
			~CClient()
			{
				if(m_hSocket != INVALID_SOCKET) 
					closesocket(m_hSocket);
				if (m_pSSL)
					SSL_free (m_pSSL);
				if (m_pSSLContext)
					SSL_CTX_free (m_pSSLContext);
				if (m_nSendFile != -1)
					_close(m_nSendFile);
			}
		private:
			//Перечисляем все возможные состояния клиента. При желании можно добавлять новые.
			enum STATES 
			{ 
				S_ACCEPTED_TCP,
				S_ACCEPTED_SSL,
				S_READING,
				S_ALL_READED,
				S_WRITING,
				S_ALL_WRITED
			};
			STATES m_stateCurrent; //Здесь хранится текущее состояние

			//Функции для установки и получения состояния
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
			const STATES GetState() const {return m_stateCurrent;}
		public:
			//Функция для обработки текужего состояния клиента
			const bool Continue(struct epoll_event *pCurrentEvent)
			{
				if (m_hSocket == INVALID_SOCKET)
					return false;

				switch (GetState())
				{
					case S_ACCEPTED_TCP:
					{
						switch (AcceptSSL())
						{
							case RET_READY:
								SetState(S_ACCEPTED_SSL, pCurrentEvent);
								break;
							case RET_ERROR:
								return false;
							default:
								return true;
						}
					}
					case S_ACCEPTED_SSL:
					{
						switch (GetSertificate())
						{
							case RET_READY:
								SetState(S_READING, pCurrentEvent);
								break;
							case RET_ERROR:
								return false;
							default:
								return true;
						}
					}
					case S_READING:
					{
						switch (ContinueRead())
						{
							case RET_READY:
								SetState(S_ALL_READED, pCurrentEvent);
								break;
							case RET_ERROR:
								return false;
							default:
								return true;
						}
					}
					case S_ALL_READED:
					{
						switch (InitRead())
						{
							case RET_READY:
								SetState(S_WRITING, pCurrentEvent);
								break;
							case RET_ERROR:
								return false;
							default:
								return true;
						}
					}
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
					case S_ALL_WRITED:
						return false;
					default:
						return false;
				}
			}
		private:
			int GetLastError(int err) const
			{
				if (m_bIsSSL)
					return SSL_get_error(m_pSSL, err);
				else
					return WSAGetLastError();
			}
			enum RETCODES
			{
				RET_WAIT,
				RET_READY,
				RET_ERROR
			};
			const RETCODES AcceptSSL()
			{
				cout << "AcceptSSL\n";
				if (!m_bIsSSL) return RET_READY;

				if (!m_pSSLContext)
					return RET_ERROR;

				if (!m_pSSL)
				{
					m_pSSL = SSL_new (m_pSSLContext);
				
					if (!m_pSSL)
						return RET_ERROR;

					SSL_set_fd (m_pSSL, m_hSocket);
				}

				const int err = SSL_accept (m_pSSL); 
				if (err == 1)
					return RET_READY;

				const int nCode = SSL_get_error(m_pSSL, err);
			
				if ((nCode == SSL_ERROR_WANT_READ) || (nCode == SSL_ERROR_WANT_WRITE))
					return RET_WAIT;

				return RET_ERROR;
			}
			const RETCODES GetSertificate()
			{
				cout << "GetSertificate\n";
				if (!m_bIsSSL) return RET_READY;

				if (!m_pSSLContext || !m_pSSL)
					return RET_ERROR;
			
				/* Get client's certificate (note: beware of dynamic allocation) - opt */
				cout << "SSL connection using " << SSL_get_cipher (m_pSSL) << "\n";

				X509* client_cert = SSL_get_peer_certificate (m_pSSL);
				if (client_cert != NULL) 
				{
					cout << "Client certificate:\n";
    
					char* str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
					if (!str)
						return RET_ERROR;

					cout << "\t subject: " << str << "\n";
					OPENSSL_free (str);
    
					str = X509_NAME_oneline (X509_get_issuer_name  (client_cert), 0, 0);
					if (!str)
						return RET_ERROR;

					cout << "\t issuer: " << str << "\n";
					OPENSSL_free (str);
    
					/* We could do all sorts of certificate verification stuff here before
						deallocating the certificate. */
    
					X509_free (client_cert);
				} 
				else
					cout << "Client does not have certificate.\n";

				return RET_READY;
			}
			const RETCODES ContinueRead()
			{
				cout << "ContinueRead bSSL=" << m_bIsSSL << "\n";
				if (m_bIsSSL && (!m_pSSLContext || !m_pSSL))
					return RET_ERROR;

				static char szBuffer[4096];
			
				//читаем данные от клиента в буфер
				int err;
				if (m_bIsSSL)
					err = SSL_read (m_pSSL, szBuffer, 4096);
				else
				{
					errno = 0;
					err = recv(m_hSocket, szBuffer, 4096, 0);
				}
				m_nLastSocketError = GetLastError(err);

				if (err > 0)
				{
					//Сохраним прочитанные данные в переменной m_vRecvBuffer
					m_vRecvBuffer.resize(m_vRecvBuffer.size()+err);
					memcpy(&m_vRecvBuffer[m_vRecvBuffer.size()-err], szBuffer, err);
		 
					//Ищем конец http заголовка в прочитанных данных
					const std::string strInputString((const char *)&m_vRecvBuffer[0]);
					if (strInputString.find("\r\n\r\n") != strInputString.npos)
						return RET_READY;

					cout << "ContinueRead return RET_WAIT err=" << err << "\n";
					return RET_WAIT;
				}
			
				if (!m_bIsSSL)
				{
					m_nLastSocketError = WSAGetLastError();
					if ((err == 0) || ((m_nLastSocketError != WSAEWOULDBLOCK) && (m_nLastSocketError != S_OK)))
						return RET_ERROR;
				}
				else
				{
					m_nLastSocketError = SSL_get_error(m_pSSL, err);
					if ((err == 0) || ((m_nLastSocketError != SSL_ERROR_WANT_READ) && (m_nLastSocketError != SSL_ERROR_WANT_WRITE)))
						return RET_ERROR;
				}
			
				cout << "ContinueRead return RET_WAIT\n";
				return RET_WAIT;
			}

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

				//Добавляем в начало ответа http заголовок
 				std::ostringstream strStream;
				strStream << 
						"HTTP/1.1 200 OK\r\n"
						<< "Content-Type: image/jpeg\r\n"
						<< "Content-Length: " << m_nFileSize << "\r\n" <<
						"\r\n";

				//Запоминаем заголовок
				m_vSendBuffer.resize(strStream.str().length());
				memcpy(&m_vSendBuffer[0], strStream.str().c_str(), strStream.str().length());

				return RET_READY;
			}
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
			const RETCODES ContinueWrite()
			{
				cout << "ContinueWrite bSSL=" << m_bIsSSL << "\n";
				if (m_bIsSSL && (!m_pSSLContext || !m_pSSL))
					return RET_ERROR;

				int err;
				if (m_bIsSSL)
					err = SSL_write (m_pSSL, &m_vSendBuffer[0], m_vSendBuffer.size());
				else
				{
					errno = 0;
					err = send(m_hSocket, (const char*)&m_vSendBuffer[0], m_vSendBuffer.size(), 0);
				}
				m_nLastSocketError = GetLastError(err);

				if (err > 0)
				{
					//Если удалось послать все данные, то переходим к следующему состоянию
					if ((size_t)err == m_vSendBuffer.size())
					{
						m_vSendBuffer.clear();
						return RET_READY;
					}

					//Если отослали не все данные, то оставим в буфере только то, что еще не послано
					vector<unsigned char> vTemp(m_vSendBuffer.size()-err);
					memcpy(&vTemp[0], &m_vSendBuffer[err], m_vSendBuffer.size()-err);
					m_vSendBuffer = vTemp;

					return RET_WAIT;
				}
	 
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

				return RET_WAIT;
			}
	 
		};
		map<SOCKET, shared_ptr<CClient> > m_mapClients; //Здесь сервер будет хранить всех клиентов

		explicit CServer(const CServer &) {} //Нам не понадобится конструктор копирования для сервера

		//События слушающего сокета
		struct epoll_event m_ListenEventTCP, m_ListenEventSSL;
		//События клиентских сокетов
		vector<struct epoll_event> m_events;
		int m_epoll;

	public:
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
			SSL_load_error_strings();
			SSLeay_add_ssl_algorithms();
			
			/* ----------------------------------------------- */
			/* Prepare TCP socket for receiving connections */

			m_epoll = epoll_create (1);
			if (m_epoll == -1)
			{
				cout << "error: epoll_create";
				return;
			}

			InitListenSocket(nPortTCP, m_ListenEventTCP);
			InitListenSocket(nPortSSL, m_ListenEventSSL);

			while(true)
			{
				m_events.resize(m_mapClients.size()+2);
				int n = epoll_wait (m_epoll, &m_events[0], m_events.size(), 5000);

				if (n == -1)
					continue;

				Callback(n);
			}
		}
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
				//Добавляем нового клиента в класс сервера
				m_mapClients[sd] = shared_ptr<CClient>(new CClient(sd, bIsSSL));
						
				auto it = m_mapClients.find(sd);
				if (it == m_mapClients.end())
					return;
						
				//Добавляем нового клиента в epoll
				struct epoll_event ev = it->second->GetEvent();
				epoll_ctl (m_epoll, EPOLL_CTL_ADD, it->first, &ev);
			}					
		}
		void Callback(const int nCount)
		{
			for (int i = 0; i < nCount; i++)
			{
				SOCKET hSocketIn = m_events[i].data.fd;

				if (m_ListenEventTCP.data.fd == (int)hSocketIn)
				{
					if (m_events[i].events & EPOLLIN) 
						AcceptClient(hSocketIn, false);

					continue;
				}
				if (m_ListenEventSSL.data.fd == (int)hSocketIn)
				{
					if (m_events[i].events & EPOLLIN) 
						AcceptClient(hSocketIn, true);
					continue;
				}
					
				auto it = m_mapClients.find(hSocketIn); //Находим клиента по сокету
				if (it == m_mapClients.end())
					continue;

				if (!it->second->Continue(&m_events[i])) //Делаем что-нибудь с клиентом
				{
					//Если клиент вернул false, то удаляем клиента из epoll и из класса сервера
					epoll_ctl (m_epoll, EPOLL_CTL_DEL, it->first, NULL);
					m_mapClients.erase(it);
					
					cout << "Delete Client, ClientsCount=" << m_mapClients.size() << "\n";
				}
			}
		}
	};
}

#endif
