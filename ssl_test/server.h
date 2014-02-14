#ifndef _SERVER
#define _SERVER
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>

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
#include <fcntl.h>
#define SET_NONBLOCK(socket)	\
	if (fcntl( socket, F_SETFL, fcntl( socket, F_GETFL, 0 ) | O_NONBLOCK ) < 0)	\
		printf("error in fcntl errno=%i\n", errno);
#define closesocket(socket)  close(socket)
#define Sleep(a) usleep(a*1000)
#define SOCKET	int
#define INVALID_SOCKET	-1
#endif


/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */
#define CERTF  HOME "ca-cert.pem"
#define KEYF  HOME  "ca-cert.pem"

#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

using namespace std;
namespace server
{
	class CClient
	{
		SOCKET m_hSocket; //Дескриптор клиентского сокета
		vector<unsigned char> m_vRecvBuffer; //В этом буфере клиент будет хранить принятые данные
		vector<unsigned char> m_vSendBuffer; //В этом буфере клиент будет хранить отправляемые данные
		
		//Указатели для взаимодействия с OpenSSL
		SSL_CTX* m_pSSLContext;
		SSL* m_pSSL;

		explicit CClient(const CClient &client) {} //Нам не понадобится конструктор копирования для клиентов
	public:
		CClient(const SOCKET hSocket) : m_hSocket(hSocket), m_pSSL(NULL), m_pSSLContext(NULL), m_stateCurrent(S_ACCEPTED_TCP)
		{
#ifdef WIN32
			const SSL_METHOD *meth = SSLv23_server_method();
#else
			SSL_METHOD *meth = SSLv23_server_method();
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
		~CClient()
		{
			if(m_hSocket != INVALID_SOCKET) 
				closesocket(m_hSocket);
			if (m_pSSL)
				SSL_free (m_pSSL);
			if (m_pSSLContext)
				SSL_CTX_free (m_pSSLContext);
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
		void SetState(const STATES state) {m_stateCurrent = state;}
		const STATES GetState() const {return m_stateCurrent;}
	public:
		//Функция для обработки текужего состояния клиента
		const bool Continue()
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
							printf ("SSL connection using %s\n", SSL_get_cipher (m_pSSL));
							SetState(S_ACCEPTED_SSL);
							break;
						case RET_ERROR:
							return false;
					}

					return true;
				}
				case S_ACCEPTED_SSL:
				{
					switch (GetSertificate())
					{
						case RET_READY:
							SetState(S_READING);
							break;
						case RET_ERROR:
							return false;
					}

					return true;
				}
				case S_READING:
				{
					switch (ContinueRead())
					{
						case RET_READY:
							SetState(S_ALL_READED);
							break;
						case RET_ERROR:
							return false;
					}

					return true;
				}
				case S_ALL_READED:
				{
					switch (InitRead())
					{
						case RET_READY:
							SetState(S_WRITING);
							break;
						case RET_ERROR:
							return false;
					}

					return true;
				}
				case S_WRITING:
				{
					switch (ContinueWrite())
					{
						case RET_READY:
							SetState(S_ALL_WRITED);
							break;
						case RET_ERROR:
							return false;
					}

					return true;
				}
				case S_ALL_WRITED:
					return false;
				default:
					return false;
			}
			return true;
		}
	private:
		enum RETCODES
		{
			RET_WAIT,
			RET_READY,
			RET_ERROR
		};
		const RETCODES AcceptSSL()
		{
			if (!m_pSSLContext) //Наш сервер предназначен только для SSL
				return RET_ERROR;

			if (!m_pSSL)
			{
				m_pSSL = SSL_new (m_pSSLContext);
				
				if (!m_pSSL)
					return RET_ERROR;

				SSL_set_fd (m_pSSL, m_hSocket);
			}

			const int err = SSL_accept (m_pSSL); 

			const int nCode = SSL_get_error(m_pSSL, err);
			if ((nCode != SSL_ERROR_WANT_READ) && (nCode != SSL_ERROR_WANT_WRITE))
				return RET_READY;

			return RET_WAIT;
		}
		const RETCODES GetSertificate()
		{
			if (!m_pSSLContext || !m_pSSL) //Наш сервер предназначен только для SSL
				return RET_ERROR;
			
			/* Get client's certificate (note: beware of dynamic allocation) - opt */

			X509* client_cert = SSL_get_peer_certificate (m_pSSL);
			if (client_cert != NULL) 
			{
				printf ("Client certificate:\n");
    
				char* str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
				if (!str)
					return RET_ERROR;

				printf ("\t subject: %s\n", str);
				OPENSSL_free (str);
    
				str = X509_NAME_oneline (X509_get_issuer_name  (client_cert), 0, 0);
				if (!str)
					return RET_ERROR;

				printf ("\t issuer: %s\n", str);
				OPENSSL_free (str);
    
				/* We could do all sorts of certificate verification stuff here before
					deallocating the certificate. */
    
				X509_free (client_cert);
			} 
			else
				printf ("Client does not have certificate.\n");

			return RET_READY;
		}
		const RETCODES ContinueRead()
		{
			if (!m_pSSLContext || !m_pSSL) //Наш сервер предназначен только для SSL
				return RET_ERROR;

			unsigned char szBuffer[4096];
			
			const int err = SSL_read (m_pSSL, szBuffer, 4096); //читаем данные от клиента в буфер
			if (err > 0)
			{
				//Сохраним прочитанные данные в переменной m_vRecvBuffer
				m_vRecvBuffer.resize(m_vRecvBuffer.size()+err);
				memcpy(&m_vRecvBuffer[m_vRecvBuffer.size()-err], szBuffer, err);
		 
				//Ищем конец http заголовка в прочитанных данных
				const std::string strInputString((const char *)&m_vRecvBuffer[0]);
				if (strInputString.find("\r\n\r\n") != -1)
					return RET_READY;

				return RET_WAIT;
			}

			const int nCode = SSL_get_error(m_pSSL, err);
			if ((nCode != SSL_ERROR_WANT_READ) && (nCode != SSL_ERROR_WANT_WRITE))
				return RET_ERROR;
			
			return RET_WAIT;
		}

		const RETCODES InitRead()
		{
			if (!m_pSSLContext || !m_pSSL) //Наш сервер предназначен только для SSL
				return RET_ERROR;

			//Преобразуем буфер в строку для удобства
			const std::string strInputString((const char *)&m_vRecvBuffer[0]);

			//Формируем html страницу с ответом сервера
			const std::string strHTML = 
				  "<html><body><h2>Hello! Your HTTP headers is:</h2><br><pre>" + 
				  strInputString.substr(0, strInputString.find("\r\n\r\n")) + 
				  "</pre></body></html>";

			//Добавляем в начало ответа http заголовок
 			std::ostringstream strStream;
			strStream << 
					"HTTP/1.1 200 OK\r\n"
					<< "Content-Type: text/html; charset=utf-8\r\n"
					<< "Content-Length: " << strHTML.length() << "\r\n" <<
					"\r\n" <<
					strHTML.c_str();

			//Запоминаем ответ, который хотим послать
			m_vSendBuffer.resize(strStream.str().length());
			memcpy(&m_vSendBuffer[0], strStream.str().c_str(), strStream.str().length());

			return RET_READY;
		}
		const RETCODES ContinueWrite()
		{
			if (!m_pSSLContext || !m_pSSL) //Наш сервер предназначен только для SSL
				return RET_ERROR;

			int err = SSL_write (m_pSSL, &m_vSendBuffer[0], m_vSendBuffer.size());
			if (err > 0)
			{
				//Если удалось послать все данные, то переходим к следующему состоянию
				if (err == m_vSendBuffer.size())
					return RET_READY;

				//Если отослали не все данные, то оставим в буфере только то, что еще не послано
				vector<unsigned char> vTemp(m_vSendBuffer.size()-err);
				memcpy(&vTemp[0], &m_vSendBuffer[err], m_vSendBuffer.size()-err);
				m_vSendBuffer = vTemp;

				return RET_WAIT;
			}
	 
			const int nCode = SSL_get_error(m_pSSL, err);
			if ((nCode != SSL_ERROR_WANT_READ) && (nCode != SSL_ERROR_WANT_WRITE))
				return RET_ERROR;

			return RET_WAIT;
		}
	 
	};

	class CServer
	{
		map<SOCKET, shared_ptr<CClient> > m_mapClients; //Здесь сервер будет хранить всех клиентов

		explicit CServer(const CServer &server) {} //Нам не понадобится конструктор копирования для сервера
	public:
		CServer()
		{
#ifdef WIN32
			WSADATA wsaData;
			if ( WSAStartup( MAKEWORD( 2, 2 ), &wsaData ) != 0 )
			{
				printf("Could not to find usable WinSock in WSAStartup\n");
				return;
			}
#endif
			SSL_load_error_strings();
			SSLeay_add_ssl_algorithms();
			
			/* ----------------------------------------------- */
			/* Prepare TCP socket for receiving connections */

			SOCKET listen_sd = socket (AF_INET, SOCK_STREAM, 0);	  CHK_ERR(listen_sd, "socket");
			SET_NONBLOCK(listen_sd);
  
			struct sockaddr_in sa_serv;
			memset (&sa_serv, '\0', sizeof(sa_serv));
			sa_serv.sin_family      = AF_INET;
			sa_serv.sin_addr.s_addr = INADDR_ANY;
			sa_serv.sin_port        = htons (1111);          /* Server Port number */
  
			int err = ::bind(listen_sd, (struct sockaddr*) &sa_serv, sizeof (sa_serv));      CHK_ERR(err, "bind");
	     
			/* Receive a TCP connection. */
			
			err = listen (listen_sd, 5);            CHK_ERR(err, "listen");

			while(true)
			{
				Sleep(1);

				struct sockaddr_in sa_cli;  
				size_t client_len = sizeof(sa_cli);
#ifdef WIN32
				const SOCKET sd = accept (listen_sd, (struct sockaddr*) &sa_cli, (int *)&client_len);
#else
				const SOCKET sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
#endif  
				Callback(sd);
			}
		}
	private:
		void Callback(const SOCKET hSocket)
		{
			if (hSocket != INVALID_SOCKET)
				m_mapClients[hSocket] = shared_ptr<CClient>(new CClient(hSocket)); //Добавляем нового клиента

			auto it = m_mapClients.begin();
			while (it != m_mapClients.end()) //Перечисляем всех клиентов
			{
			   if (!it->second->Continue()) //Делаем что-нибудь с клиентом
				  m_mapClients.erase(it++); //Если клиент вернул false, то удаляем клиента
			   else
				  it++;
			}
		}
	};
}

#endif
