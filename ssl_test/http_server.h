#include "server.h"
#include "RequestWorker.h"
#include <unordered_map>

#define ROOT_PATH		"./wwwroot"
#define ERROR_PAGE		"error.html"
#define DEFAULT_PAGE	"index.html"

namespace server
{
	class CHttpClient
	{
		int m_nSendFile; //дескриптор файла
		off_t m_nFilePos; //позиция в файле
		unsigned long long m_nFileSize; //размер файла
		time_t m_tmLastSocketTime;
		bool m_bKeepAlive;

		enum STATES	{
			S_READING_HEADER,
			S_READING_BODY,
			S_WRITING_HEADER,
			S_WRITING_BODY,
			S_ERROR
		};
		STATES m_stateCurrent; //текущее состояние клиента
		unordered_map<string, string> m_mapHeader, m_mapVariables;

		void SetState(const STATES state) 
		{
			m_tmLastSocketTime = time(NULL);
			m_stateCurrent = state;
		}

		void ParseGETVariables()
		{
			if (m_mapHeader.find("GET_Query") == m_mapHeader.end())
				return;

			string strTemp = m_mapHeader["GET_Query"];
			while(strTemp.length())
			{
				string strLeft = "";
				const int nPos = strTemp.find("&");
				if (nPos == -1)
				{
					strLeft = strTemp;
					strTemp = "";
				}
				else
				{
					strLeft = strTemp.substr(0, nPos);
					string strRight = strTemp.substr(nPos+1);
					strTemp = strRight;
				}

				const int nPosEQ = strLeft.find("=");
				if (nPosEQ == -1)
					m_mapVariables[strLeft] = "";
				else
					m_mapVariables[strLeft.substr(0, nPosEQ)] = strLeft.substr(nPosEQ+1);
			}
		}
		const bool ParseHeader(const string strHeader) //парсинг заголовка http запроса
		{
			m_mapHeader["Method"] = strHeader.substr(0, strHeader.find(" ") > 0 ? strHeader.find(" ") : 0);
			if (m_mapHeader["Method"] != "GET") return false;
			
			const int nPathSize = strHeader.find(" ", m_mapHeader["Method"].length()+1)-m_mapHeader["Method"].length()-1;
			if (nPathSize < 0)	return false;
			m_mapHeader["Path"] = strHeader.substr(m_mapHeader["Method"].length()+1, nPathSize);

			const int nQueryPos = m_mapHeader["Path"].find("?");
			if (nQueryPos != -1)
			{
				m_mapHeader["GET_Query"] = m_mapHeader["Path"].substr(nQueryPos+1);
				ParseGETVariables();
			}
			
			m_bKeepAlive = (strHeader.find(KEEP_ALIVE) != strHeader.npos);
			return true;
		}
		const MESSAGE OnReadHeader(const string strHeader, shared_ptr<vector<unsigned char>> pvBuffer)
		{
			cout << "Header readed \n" << strHeader;
			if (!ParseHeader(strHeader))	m_mapHeader["Path"] = ERROR_PAGE;
			if (m_mapHeader["Path"] == "/") m_mapHeader["Path"] += DEFAULT_PAGE;

			if (m_mapVariables.size())
				return CRequestWorker::GetResponce(m_bKeepAlive, m_mapHeader, m_mapVariables, pvBuffer);

			cout << "open file" << ROOT_PATH << m_mapHeader["Path"].c_str() << "\n";
			if ((m_nSendFile = _open((ROOT_PATH+m_mapHeader["Path"]).c_str(), O_RDONLY|O_BINARY)) == -1)
				return PLEASE_STOP;
			
			struct stat stat_buf;
			if (fstat(m_nSendFile, &stat_buf) == -1)
				return PLEASE_STOP;

			m_nFileSize = stat_buf.st_size;

			//Добавляем в начало ответа http заголовок
			string strResponce = 
				"HTTP/1.1 200 OK\r\n"
				"Content-Length: "  + to_string(m_nFileSize) + "\r\n";
			if (m_bKeepAlive) strResponce += KEEP_ALIVE "\r\n";
			
			strResponce += "\r\n";

			//Запоминаем заголовок
			pvBuffer->resize(strResponce.length());
			move(strResponce.c_str(), strResponce.c_str()+strResponce.length(), &pvBuffer->at(0));
			return PLEASE_WRITE_BUFFER;
		}
		explicit CHttpClient(CHttpClient &client);
		const MESSAGE CleanAndInit()
		{
			if (m_nSendFile != -1)
			{
				_close(m_nSendFile);
				m_nSendFile = -1;
			}
			m_nFilePos = 0;
			m_nFileSize = 0;
			m_stateCurrent = S_READING_HEADER;
			m_tmLastSocketTime = time(NULL);
			m_bKeepAlive = false;
			return PLEASE_READ;
		}
	public:
		CHttpClient() : m_nSendFile(-1) 
		{
			CleanAndInit();
		}
		~CHttpClient() 
		{
			if (m_nSendFile != -1) _close(m_nSendFile);
		}
			
		const MESSAGE OnTimer(shared_ptr<vector<unsigned char>> pvBuffer)
		{
#ifndef _DEBUG
			if (time(NULL) - m_tmLastSocketTime > 5) 
				return PLEASE_STOP; //Timeout 5 sec
#endif
			return PLEASE_READ;
		}
		const MESSAGE OnAccepted(shared_ptr<vector<unsigned char>> pvBuffer) {return PLEASE_READ;}
		const MESSAGE OnWrote(shared_ptr<vector<unsigned char>> pvBuffer)
		{
			switch(m_stateCurrent) {
				case S_WRITING_HEADER:
					if (m_nSendFile == -1)
						return PLEASE_STOP;

					SetState(S_WRITING_BODY);
					pvBuffer->resize(sizeof(int));
					memcpy(&pvBuffer->at(0), &m_nSendFile, pvBuffer->size());

					cout << "send PLEASE_WRITE_FILE m_nSendFile=" << m_nSendFile << "\n";
					return PLEASE_WRITE_FILE;
				default:
					return m_bKeepAlive ? CleanAndInit() : PLEASE_STOP;
			}
		}
		const MESSAGE OnRead(shared_ptr<vector<unsigned char>> pvBuffer)
		{
			switch(m_stateCurrent) {
				case S_READING_HEADER:
				{
					//Ищем конец http заголовка в прочитанных данных
					const std::string strInputString((const char *)&pvBuffer->at(0));
					if (strInputString.find("\r\n\r\n") == strInputString.npos)
						return PLEASE_READ;

					switch(OnReadHeader(strInputString.substr(0, strInputString.find("\r\n\r\n")+4), pvBuffer)) {
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
				default: 
					return PLEASE_STOP;
			}
		}
	};
}