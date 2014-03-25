#include "http_server.h"
using namespace server;

CServer<CHttpClient> s(8085, 1111);

int main() {return 0;}

