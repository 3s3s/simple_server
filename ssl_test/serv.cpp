/* serv.cpp  -  Minimal ssleay server for Unix
   30.9.1996, Sampo Kellomaki <sampo@iki.fi> */


/* mangled to work with SSLeay-0.9.0b and OpenSSL 0.9.2b
   Simplified to be even more minimal
   12/98 - 4/99 Wade Scholine <wades@mail.cybg.com> */

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
#endif


/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */
#define CERTF  HOME "ca-cert.pem"
#define KEYF  HOME  "ca-cert.pem"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }


int main ()
{
  int err;
  int listen_sd;
  struct sockaddr_in sa_serv;
  struct sockaddr_in sa_cli;
  SSL_CTX* ctx;
  SSL*     ssl;
  X509*    client_cert;
  char*    str;
  
#ifdef WIN32
	WSADATA wsaData;
	if ( WSAStartup( MAKEWORD( 2, 2 ), &wsaData ) != 0 )
	{
		printf("Could not to find usable WinSock in WSAStartup\n");
		return 0;
	}
#endif
  /* SSL preliminaries. We keep the certificate and key with the context. */

  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();
#ifdef WIN32
  const SSL_METHOD *meth = SSLv23_server_method();
#else
  SSL_METHOD *meth = SSLv23_server_method();
#endif
  ctx = SSL_CTX_new (meth);
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    exit(2);
  }
  
  if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(3);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(4);
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr,"Private key does not match the certificate public key\n");
    exit(5);
  }

  /* ----------------------------------------------- */
  /* Prepare TCP socket for receiving connections */

  listen_sd = socket (AF_INET, SOCK_STREAM, 0);	  CHK_ERR(listen_sd, "socket");
  SET_NONBLOCK(listen_sd);
  
  memset (&sa_serv, '\0', sizeof(sa_serv));
  sa_serv.sin_family      = AF_INET;
  sa_serv.sin_addr.s_addr = INADDR_ANY;
  sa_serv.sin_port        = htons (1111);          /* Server Port number */
  
  err = bind(listen_sd, (struct sockaddr*) &sa_serv,
	     sizeof (sa_serv));                   CHK_ERR(err, "bind");
	     
  /* Receive a TCP connection. */
	     
  err = listen (listen_sd, 5);                    CHK_ERR(err, "listen");
  
  size_t client_len = sizeof(sa_cli);

  int sd = -1;
  while(sd  == -1)
  {
	  Sleep(1);
#ifdef WIN32
	sd = accept (listen_sd, (struct sockaddr*) &sa_cli, (int *)&client_len);
#else
	sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
#endif  
  }
  CHK_ERR(sd, "accept");
  closesocket (listen_sd);

  SET_NONBLOCK(sd);

  printf ("Connection from %lx, port %x\n",
	  sa_cli.sin_addr.s_addr, sa_cli.sin_port);
  
  /* ----------------------------------------------- */
  /* TCP connection is ready. Do server side SSL. */

  ssl = SSL_new (ctx);                           CHK_NULL(ssl);
  SSL_set_fd (ssl, sd);

  while(1)
  {
	  Sleep(1);
	  err = SSL_accept (ssl); 

	  const int nCode = SSL_get_error(ssl, err);
	  if ((nCode != SSL_ERROR_WANT_READ) && (nCode != SSL_ERROR_WANT_WRITE))
		  break;
  }
  CHK_SSL(err);
  
  /* Get the cipher - opt */
  
  printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
  
  /* Get client's certificate (note: beware of dynamic allocation) - opt */

  client_cert = SSL_get_peer_certificate (ssl);
  if (client_cert != NULL) {
    printf ("Client certificate:\n");
    
    str = X509_NAME_oneline (X509_get_subject_name (client_cert), 0, 0);
    CHK_NULL(str);
    printf ("\t subject: %s\n", str);
    OPENSSL_free (str);
    
    str = X509_NAME_oneline (X509_get_issuer_name  (client_cert), 0, 0);
    CHK_NULL(str);
    printf ("\t issuer: %s\n", str);
    OPENSSL_free (str);
    
    /* We could do all sorts of certificate verification stuff here before
       deallocating the certificate. */
    
    X509_free (client_cert);
  } else
    printf ("Client does not have certificate.\n");

  /* DATA EXCHANGE - Receive message and send reply. */

  std::vector<unsigned char> vBuffer(4096); //выделяем буфер для входных данных
  memset(&vBuffer[0], 0, vBuffer.size()); //заполняем буфер нулями

  size_t nCurrentPos = 0;
  while (nCurrentPos < vBuffer.size()-1)
  {
	  err = SSL_read (ssl, &vBuffer[nCurrentPos], vBuffer.size() - nCurrentPos - 1); //читаем в цикле данные от клиента в буфер
	  if (err > 0)
	  {
		  nCurrentPos += err;
		 
		  const std::string strInputString((const char *)&vBuffer[0]);
		  if (strInputString.find("\r\n\r\n") != -1) //Если найден конец http заголовка, то выходим из цикла
			  break;

		  continue;
	  }
	 
	  const int nCode = SSL_get_error(ssl, err);
	  if ((nCode != SSL_ERROR_WANT_READ) && (nCode != SSL_ERROR_WANT_WRITE))
		  break;
  }

  //Преобразуем буфер в строку для удобства
  const std::string strInputString((const char *)&vBuffer[0]);

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

	//Цикл для отправки ответа клиенту.
	nCurrentPos = 0;
	while(nCurrentPos < strStream.str().length())
	{
		err = SSL_write (ssl, strStream.str().c_str(), strStream.str().length());
		if (err > 0)
		{
			nCurrentPos += err;
			continue;
		}
	 
		const int nCode = SSL_get_error(ssl, err);
		if ((nCode != SSL_ERROR_WANT_READ) && (nCode != SSL_ERROR_WANT_WRITE))
			break;
	}

  /* Clean up. */

  closesocket (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);
  return 0;
}
/* EOF - serv.cpp */
