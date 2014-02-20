Кроссплатформенный сервер с неблокирующими сокетами. Часть 4
Эта статья продолжает мои предыдущие:
Простейший кросcплатформенный сервер с поддержкой ssl
Кроссплатформенный https сервер с неблокирующими сокетами 
Кроссплатформенный https сервер с неблокирующими сокетами. Часть 2
Кроссплатформенный https сервер с неблокирующими сокетами. Часть 3

В своих статьях я поэтапно расписываю процесс создания однопоточного кроссплатформенного сервера на неблокирующих сокетах.
Во всех предыдущих статьях, сервер принимал и отправлял сообщения только по ssl протоколу. В этой статье я опишу добавление в сервер
поддержки обычного нешифрованного tcp протокола и научу сервер отправлять браузеру графический файл.
Но сначала немного пройдусь по комментариям к предыдущим статьям.

1. Я послушал советов избавиться от функции printf в пользу std::cout.
2. Умные люди доказали мне, что std::memcpy и std::copy для компилятора одно и то же. 
Мне memcpy удобней, поэтому буду продолжать пользоваться ей.
3. Я перенес все ранние релизы и буду переносить будующие на GitHub, хотя клиент для Windows у них, на мой взгляд, ужасен.
4. Кто считает, что строчки
			const char on = 1;
			setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) );
помогут избежать ошибки "Address already in use" при аварийном перезапуске сервера - жестоко ошибаются. Не помогут.
5. Тем, кто считает, что разные классы всегда нужно разносить по разным файлам, подолью масла: я хочу перенести класс CClient в 
приватную секцию класса CServer!

Было:
CClient
{
***
};
CServer
{
***
};

Стало:
CServer
{
	CClient
	{
	***
	};
***
};

Теперь, если сервер станет библиотекой, ни у кого не должно возникнуть мысли об использовании класса CClient: это служебный класс, предназначенный
исключительно для взаимодействия с классом CServer.

6. И еще на мой взгляд, функция main() - атавизм, доставшийся программистам от СИ. В С++ она лишняя. Но компиляторы пока этого не знают к сожалению.
Но я решил "наказать" эту ненужную функцию, отобрав у нее возможность что-либо сделать - изменил файл serv.cpp следующим образом:

#include "server.h"

const server::CServer s(8085, 1111);

int main() {return 0;}


Теперь о главном.
Добавление в сервер поддержки нешифрованных tcp соединений.
Нешифрованные и шифрованные соединения в серверах обычно принимаются на разные порты поэтому первое, что нужно сделать - это изменить конструктор
сервера и добавить переменных, для еще одного слушающего сокета.

Вместо
struct epoll_event m_ListenEvent;
пишем в классе сервера
struct epoll_event m_ListenEventTCP, m_ListenEventSSL;

В конструкторе сервера добавим номера портов и код для линукса, который не позволит аварийно завершиться серверу в случае ошибки в TCP операциях:
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

Напишем отдельные функции для инициации слушающих сокетов и для добавления нового клиента:
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

Теперь в клиенте добавим переменную m_bIsSSL, которую будем инициировать в конструкторе, а потом изменим callback функции так,
чтобы они могли работать с TCP соединениями:
Вместо
		const RETCODES AcceptSSL()
		{
			if (!m_pSSLContext) //Наш сервер предназначен только для SSL
				return RET_ERROR;
Тепрь будет:
			const RETCODES AcceptSSL()
			{
				cout << "AcceptSSL\n";
				if (!m_bIsSSL) return RET_READY;

				if (!m_pSSLContext)
					return RET_ERROR;

Как видим, проще некуда: TCP функция accept не требует никаких дополнительных телодвижений для того, чтобы начать принимать и отдавать данные.
Никаких сертификатов для TCP не нужно, поэтому начало соответствующей функции будет теперь выглядеть так:
			const RETCODES GetSertificate()
			{
				cout << "GetSertificate\n";
				if (!m_bIsSSL) return RET_READY;

В функции, читающей данные от клиента ContinueRead() нужно вместо
			unsigned char szBuffer[4096];
			
			const int err = SSL_read (m_pSSL, szBuffer, 4096); //читаем данные от клиента в буфер
написать код:

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

В этой же функции нужно теперь добавить код обработки ошибок для TCP соединения. Как и в случае SSL, ошибкой будет
если функция приема сообщения вернет отрицательное или нулевое значение. Но так как у нас неблокирующие сокеты,
то ошибка WSAEWOULDBLOCK в Windows и EWOULDBLOCK в Linux означает, что все нормально, просто нужно еще подождать.
Добавим такие макросы:
#ifndef _WIN32
#define S_OK				0
#define WSAEWOULDBLOCK			EWOULDBLOCK
#define WSAGetLastError()		errno
#endif

И такой код в функцию ContinueRead:
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

а функцию CClient::GetLastError мы определим так
		private:
			int GetLastError(int err) const
			{
				if (m_bIsSSL)
					return SSL_get_error(m_pSSL, err);
				else
					return WSAGetLastError();
			}

Совершенно аналогичным образом исправим функцию отправки сообщений ContinueWrite и наш однопоточный кроссплатформенный сервер готов для приема tcp и ssl
соединений от клиентов, чтобы отдать им заголовки запроса.
Давайте еще научим сегодня наш сервер отдавать клиентам файлы.
В принципе ничего в этом особенного нет если не считать, что в Linux для отправки файла есть более быстрый способ чем в других системах: функция sendfile.
Чтобы код был единообразным, я предлагаю поступить с sendfile так же, как мы поступали с epoll: написать эмулятор этой функции для всех систем кроме Linux.

Эмуляция функции sendfile 
1. Создадим пустые файлы "sendfile.h", "sendfile.cpp" и добавим их в проект Visual Studio.
2. В sendfile.h поместим такой код:
#ifndef __linux__
#ifndef _SENDFILE_H
#define _SENDFILE_H
#include <sys/types.h>

unsigned long long sendfile(int out_fd, int in_fd, off_t *offset, size_t count);

#endif
#endif
3. В sendfile.cpp поместим такой:

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

4. Добавим в класс сервера необходимые включения так, чтобы в Linux использовались стандартные функции, а в остальных системах - наши.
Кроме этого, добавим включение для работы с файлами и определим путь к файлу, который будем посылать клиенту:
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


5. Добавим в класс клиента файловый дескриптор и текущую позицию
	class CClient
	{
		int m_nSendFile;
		off_t m_nFilePos;
		unsigned long long m_nFileSize;

6. Изменяем функцию InitRead()
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
7. Добавляем функции для посылки файла по протоколам tcp и ssl:
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
8. Изменяем логику callback функции клиента:
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
Наш сервер готов!
Теперь он умеет отправлять не только буфер, но и файлы.
Возможно кто-то заметил, что в классе клиента добавилась переменная "m_nLastSocketError". Дело в том, что в предыдущих версиях сервера
мы всегда ждали от сокетов любые событий, переменная m_nLastSocketError поможет нам модифицировать функцию CClient::SetState так, чтобы функция epoll
от сокетов ждала только тех событий, которые нужны в данный момент.
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


Для компиляциив Visual Studio 2012, откройте файл ssl_test.sln
Для компиляции в Linux файлы epoll.h, epoll.cpp, sendfile.h и sendfile.cpp не нужны, чтобы все работало достаточно скопировать в одну директорию файлы: serv.cpp, server.h, ca-cert.pem, создать
директорию wwwroot и скопировать туда файл ./wwwroot/festooningloops.jpg, потом в командной строке набрать: «g++ -std=c++0x -L/usr/lib -lssl -lcrypto serv.cpp»
Кто зачем-то хочет видеть предупреждения компилятора, добавьте ему опцию -Wall.

