#include "server.h"

#define ROOT_PATH		"./wwwroot"
#define ERROR_PAGE		"error.html"
#define DEFAULT_PAGE	"index.html"

namespace server
{
	class CHttpClient
	{
		int m_nSendFile;
		off_t m_nFilePos;
		unsigned long long m_nFileSize;

		enum STATES	{
			S_READING_HEADER,
			S_READING_BODY,
			S_WRITING_HEADER,
			S_WRITING_BODY,
			S_ERROR
		};
		STATES m_stateCurrent;
		map<string, string> m_mapHeader;

		void SetState(const STATES state) {m_stateCurrent = state;}
		const bool ParseHeader(const string strHeader)
		{
			m_mapHeader["Method"] = strHeader.substr(0, strHeader.find(" ") > 0 ? strHeader.find(" ") : 0);
			if (m_mapHeader["Method"] != "GET") return false;
			
			const int nPathSize = strHeader.find(" ", m_mapHeader["Method"].length()+1)-m_mapHeader["Method"].length()-1;
			if (nPathSize < 0)	return false;
			m_mapHeader["Path"] = strHeader.substr(m_mapHeader["Method"].length()+1, nPathSize);
			
			return true;
		}
		const MESSAGE OnReadedHeader(const string strHeader, shared_ptr<vector<unsigned char>> pvBuffer)
		{
			cout << "Header readed\n";
			if (!ParseHeader(strHeader))	m_mapHeader["Path"] = ERROR_PAGE;
			if (m_mapHeader["Path"] == "/") m_mapHeader["Path"] += DEFAULT_PAGE;

			cout << "open file" << ROOT_PATH << m_mapHeader["Path"].c_str() << "\n";
			if ((m_nSendFile = _open((ROOT_PATH+m_mapHeader["Path"]).c_str(), O_RDONLY|O_BINARY)) == -1)
				return PLEASE_STOP;
			
			struct stat stat_buf;
			if (fstat(m_nSendFile, &stat_buf) == -1)
				return PLEASE_STOP;

			m_nFileSize = stat_buf.st_size;

			//Добавляем в начало ответа http заголовок
			std::ostringstream strStream;
			strStream << 
				"HTTP/1.1 200 OK\r\n"
				<< "Content-Length: " << m_nFileSize << "\r\n" <<
				"\r\n";

			//Запоминаем заголовок
			pvBuffer->resize(strStream.str().length());
			memcpy(&pvBuffer->at(0), strStream.str().c_str(), strStream.str().length());
			return PLEASE_WRITE_BUFFER;
		}
		explicit CHttpClient(CHttpClient &client) {}
	public:
		CHttpClient() : m_nSendFile(-1), m_nFilePos(0), m_nFileSize(0), m_stateCurrent(S_READING_HEADER) {}
		~CHttpClient()
		{
			if (m_nSendFile != -1) _close(m_nSendFile);
		}
			
		const MESSAGE OnAccepted(shared_ptr<vector<unsigned char>> pvBuffer) {return PLEASE_READ;}
		const MESSAGE OnWrited(shared_ptr<vector<unsigned char>> pvBuffer)
		{
			switch(m_stateCurrent) {
				case S_WRITING_HEADER:
					if (m_nSendFile == -1)
						return PLEASE_STOP;

					SetState(S_WRITING_BODY);
					pvBuffer->resize(sizeof(int));
					memcpy(&pvBuffer->at(0), &m_nSendFile, pvBuffer->size());
					return PLEASE_WRITE_FILE;
				default:
					return PLEASE_STOP;
			}
		}
		const MESSAGE OnReaded(shared_ptr<vector<unsigned char>> pvBuffer)
		{
			switch(m_stateCurrent) {
				case S_READING_HEADER:
				{
					//Ищем конец http заголовка в прочитанных данных
					const std::string strInputString((const char *)&pvBuffer->at(0));
					if (strInputString.find("\r\n\r\n") == strInputString.npos)
						return PLEASE_READ;

					switch(OnReadedHeader(strInputString.substr(0, strInputString.find("\r\n\r\n")+4), pvBuffer)) {
						case PLEASE_READ:
							SetState(S_READING_BODY);
							return PLEASE_READ;
						case PLEASE_WRITE_BUFFER:
							SetState(S_WRITING_HEADER);
							return PLEASE_WRITE_BUFFER;
						default:
							SetState(S_ERROR);
							return PLEASE_STOP;
					}
				}
				default: return PLEASE_STOP;
			}
		}
	};
}