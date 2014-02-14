simple_server
=============

Light C++ library for create servers

EN:
I start writing this library from this simple OpenSSL example.
In next release i change this code, so it will be compile in Visual Studio.

*********************************************************************************
RU: 
Я начну писать эту библиотеку с простого примера из иходников OpenSSL.
В следующем релизе я изменю этот пимер так, чтобы он компилировалcя в Visual Studio.


Version 0.1:

1. Add OpenSSL binaries for Windows
2. Add Visual Studio Project
3. Details: http://habrahabr.ru/post/211474/ (in Russian)

**********************************************************************************
Version 0.11:

EN:
Add base support for nonblocking sockets. Details: http://habrahabr.ru/post/211661/ (in Russian)

RU:
Добавлена базовая поддержка неблокирующих сокетов.

**********************************************************************************
Version 0.12:

EH:
Add server functionality: server may work now with requests from any count of clients. Details: http://habrahabr.ru/post/211853/ (in Russian)

RU:
Добавлена серверная функциональность: сервер теперь может обрабатывать запросы от любого количества клиентов

**********************************************************************************
Version 0.13:

EH:
Add "epoll" support for linux and "select" for other platforms. Details: http://habrahabr.ru/post/212101/ (in Russian)

RU:
Добавлена поддержка "epoll" для linux и "select" для остальных платформ


