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
		string m_strLastError;
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

					if (nColumnCount > 100)
						nColumnCount = 100;
						
					vector<string> row;
					for (int n=0; n<nColumnCount; n++)
					{
						string str = "";
						if (ppszColTextArray[n])
							str = ppszColTextArray[n];
							
						row.push_back(str);
					}

					pTable->push_back(row);
					
					if (pTable->size() > 100)
						return 1;
					return 0;
				}
			};

			char *szErrMsg = 0;
			int rc = sqlite3_exec(m_pBase, strSQL.c_str(), CLocal::Callback, &m_Table, &szErrMsg);

			if( rc != SQLITE_OK )
			{
				m_strLastError = szErrMsg;
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
			if (strRet == "[]" && m_strLastError.length())
				strRet = m_strLastError;
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
			{
				cout << "!IsValidRequest return1\r\n";
				return false;
			}
			if ((mapVariables.find(REQ_PASSWORD) == mapVariables.end()) || (mapVariables.at(REQ_PASSWORD) != ALLOWED_PASSWORD))
			{
				cout << "!IsValidRequest return2\r\n";
				return false;
			}
			if ((mapVariables.find(REQ_SQL) == mapVariables.end()) || (mapVariables.at(REQ_SQL) == ""))
			{
				cout << "!IsValidRequest return3\r\n";
				return false;
			}
			return true;
		}
	public:
		static MESSAGE GetResponce(const bool bKeepAlive, const unordered_map<string, string> &mapHeader, const unordered_map<string, string> &mapVariables, shared_ptr<vector<unsigned char>> pvBuffer)
		{
			cout << "RequestWirker GetResponce start\r\n";
			if (!IsValidRequest(mapVariables))
			{
				cout << "!IsValidRequest return PLEASE_STOP\r\n";
				return PLEASE_STOP;
			}

			cout << "GetResponce continue step1\r\n";
			string strSQLEncodded = mapVariables.at(REQ_SQL);
			while (strSQLEncodded.find("+") != -1) replace(strSQLEncodded, "+", "%20");

			const string strSQL = URLDecode(strSQLEncodded);
			const string strDBName = URLEncode(mapVariables.at(REQ_USER)+mapVariables.at(REQ_PASSWORD)+".db");

			cout << "GetResponce continue step2\r\n";
			CSQLiteHelper base(strDBName);
			cout << "GetResponce continue step3 SQL=" << strSQL.c_str() <<"\r\n";
			base.ExecuteSQL(strSQL);
			cout << "GetResponce continue step4\r\n";

			string strBody = base.toJSON();

			cout << "GetResponce continue step5\r\n";
			//Добавляем в начало ответа http заголовок
			string strResponce = 
				"HTTP/1.1 200 OK\r\n"
				"Content-Type: application/json\r\n"
				"Content-Length: "  + to_string(strBody.size()) + "\r\n";
			if (bKeepAlive) strResponce += KEEP_ALIVE "\r\n";
			
			strResponce += "\r\n" + strBody;

			cout << "GetResponce continue step6\r\n";
			//Запоминаем заголовок
			pvBuffer->resize(strResponce.length());
			move(strResponce.c_str(), strResponce.c_str()+strResponce.length(), &pvBuffer->at(0));
			cout << "GetResponce end\r\n";
			return PLEASE_WRITE_BUFFER;
		}
	};
}