#include "server.h"
#include "Settings.h"
#include "sqlite/sqlite3.h"
#include <curl/curl.h>
#include <unordered_map>

#ifdef WIN32
#include <direct.h>
#define _mkdir(a, b)	mkdir(a)
#else
#define _mkdir	mkdir
#endif

namespace server
{
	class CSQLiteHelper
	{
		sqlite3 *m_pBase;
		vector<vector<string> > m_Table;
		static sqlite3 *CreateDatabase(const string strName)
		{
			_mkdir(DB_DIRS, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

			const string strFilePath = DB_DIRS "/" + strName;
			sqlite3 *pDataBase = 0;
			char *szErrMsg = 0;
			int rc = sqlite3_open(strFilePath.c_str(), &pDataBase);
			if( rc != SQLITE_OK )
				sqlite3_free(szErrMsg);

			return pDataBase;
		}
	public:
		CSQLiteHelper(const string strName) : m_pBase(CSQLiteHelper::CreateDatabase(strName))
		{
		}
		~CSQLiteHelper()
		{
			if (m_pBase)
				sqlite3_close(m_pBase);
		}

		void ExecuteSQL(const string strSQL)
		{
			if (!m_pBase) return;

			class CLocal
			{
			public:
				static int Callback(void *lParam, int nColumnCount, char **ppszColTextArray, char **azColName)
				{
					vector<vector<string> > *pTable = (vector<vector<string> > *)lParam;

					vector<string> row;
					for (int n=0; n<nColumnCount; n++)
						row.push_back(ppszColTextArray[n]);

					pTable->push_back(row);
					return 0;
				}
			};

			char *szErrMsg = 0;
			int rc = sqlite3_exec(m_pBase, strSQL.c_str(), CLocal::Callback, &m_Table, &szErrMsg);

			if( rc != SQLITE_OK )
			{
				sqlite3_free(szErrMsg);
			}
		}

		const string toJSON() const
		{
			if (!m_pBase) return "[error]";
			
			string strRet = "[";
			for (size_t nRow=0; nRow<m_Table.size(); nRow++)
			{
				string strRow = "[";
				for (size_t nCol=0; nCol<m_Table[nRow].size(); nCol++)
				{
					strRow += "'"+m_Table[nRow][nCol]+"'";
					if (nCol < m_Table[nRow].size()-1)
						strRow += ", ";
				}
				strRow += "]";

				if (strRet != "[")
					strRet += ", ";
				strRet += strRow;
			}
			strRet += "]";
			return strRet;
		}
	};
	class CRequestWorker
	{
		static bool replace(std::string& str, const std::string& from, const std::string& to) {
			size_t start_pos = str.find(from);
			if(start_pos == std::string::npos)
				return false;
			str.replace(start_pos, from.length(), to);
			return true;
		}
		static string URLDecode(string str)
		{
			int nOut;
			char *pszDecodded = curl_easy_unescape(NULL, str.c_str() , str.length(), &nOut );
			if (!pszDecodded)
				return str;

			string strRet = pszDecodded;
			curl_free(pszDecodded);

			return strRet;

		}
		static string URLEncode(string str)
		{
			char *pszEncodded = curl_easy_escape(NULL, str.c_str() , str.length() );
			if (!pszEncodded)
				return str;

			string strRet = pszEncodded;
			curl_free(pszEncodded);

			return strRet;
		}
		static bool IsValidRequest(const unordered_map<string, string> &mapVariables)
		{
			if ((mapVariables.find(REQ_USER) == mapVariables.end()) || (mapVariables.at(REQ_USER) != ALLOWED_USER))
				return false;
			if ((mapVariables.find(REQ_PASSWORD) == mapVariables.end()) || (mapVariables.at(REQ_PASSWORD) != ALLOWED_PASSWORD))
				return false;
			if ((mapVariables.find(REQ_SQL) == mapVariables.end()) || (mapVariables.at(REQ_SQL) == ""))
				return false;
			return true;
		}
	public:
		static MESSAGE GetResponce(const bool bKeepAlive, const unordered_map<string, string> &mapHeader, const unordered_map<string, string> &mapVariables, shared_ptr<vector<unsigned char>> pvBuffer)
		{
			if (!IsValidRequest(mapVariables))
				return PLEASE_STOP;

			string strSQLEncodded = mapVariables.at(REQ_SQL);
			while (strSQLEncodded.find("+") != -1) replace(strSQLEncodded, "+", "%20");

			const string strSQL = URLDecode(strSQLEncodded);
			const string strDBName = URLEncode(mapVariables.at(REQ_USER)+mapVariables.at(REQ_PASSWORD)+".db");

			CSQLiteHelper base(strDBName);
			base.ExecuteSQL(strSQL);

			string strBody = base.toJSON();

			//Добавляем в начало ответа http заголовок
			string strResponce = 
				"HTTP/1.1 200 OK\r\n"
				"Content-Type: application/json\r\n"
				"Content-Length: "  + to_string(strBody.size()) + "\r\n";
			if (bKeepAlive) strResponce += KEEP_ALIVE "\r\n";
			
			strResponce += "\r\n" + strBody;

			//Запоминаем заголовок
			pvBuffer->resize(strResponce.length());
			move(strResponce.c_str(), strResponce.c_str()+strResponce.length(), &pvBuffer->at(0));
			return PLEASE_WRITE_BUFFER;
		}
	};
}