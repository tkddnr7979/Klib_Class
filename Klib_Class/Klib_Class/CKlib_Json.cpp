#include"pch.h"
#include "CKlib_Json.h"
#include <Windows.h>


CKlib_Json::CKlib_Json() {
	//std::lock_guard<std::mutex> lock(mtx);
	jv[""] = 0; // Initialize with an empty key
	jv.clear(); // Clear the JSON value
}

CKlib_Json::CKlib_Json(const CKlib_Json& other) {
	//std::lock_guard<std::mutex> lock(mtx);
	jv = other.jv; // Copy the JSON value
}

CKlib_Json& CKlib_Json::operator=(const CKlib_Json& other)
{
	//std::lock_guard<std::mutex> lock(mtx);
	//std::lock_guard<std::mutex> lock(other.mtx);

	if (this != &other) {
		std::lock_guard<std::mutex> lock(mtx);
		jv = other.jv; // Copy the JSON value
	}
}

const std::string CKlib_Json::from_file(const std::string fileName)
{
	std::lock_guard<std::mutex> lock(mtx);

	std::string rtn_error_msg;

	try {
		if (fileName.size() > 0) {

			jv.clear();

			// klib 사용 체크(sysMon.jsn는 예외)
			static const std::string sysMonFilePath = "C:\\comtrue\\shdlp\\jsn\\sysMon.jsn";
			ReadJsonFile(sysMonFilePath, jv, rtn_error_msg);
			{
				std::string debugLog = "[ctrjson] Use Klib check : ";
				debugLog.append(get_str("useKlib", 0));
				OutputDebugStringA(debugLog.c_str());
			}

			if (get_int("useKlib", 0) == 1
				&& fileName.c_str() != sysMonFilePath.c_str()) {

				// klib를 이용한 복호화
			}
			else {
				ReadJsonFile(fileName, jv, rtn_error_msg);
			}
		}
	}
	catch (std::exception& ex) {
		rtn_error_msg = "[shdlpKlib] json from file - exception : ";
		rtn_error_msg += ex.what();
	}

	return rtn_error_msg;
}

bool CKlib_Json::from_text(const char* text)
{
	std::lock_guard<std::mutex> lock(mtx);

	bool rtn = false;

	try {
		if (text != nullptr && *text != '\0') {
			Json::Reader().parse(text, jv);
		}

		rtn = true;
	}
	catch (std::exception ex) {
		rtn = false;
	}


	return rtn;
}

const std::string CKlib_Json::to_text(const bool bFastmode)
{
	std::lock_guard<std::mutex> lock(mtx);
	
	return bFastmode
		? Json::FastWriter().write(jv).c_str()
		: Json::StyledWriter().write(jv).c_str();
}

const CKlib_Json CKlib_Json::get_part(const char* key, ...)
{
	std::lock_guard<std::mutex> lock(mtx);
	
	CKlib_Json part;
	va_list arg = 0;


	// 요구하는 key에 대응되는 값 찾기
	va_start(arg, key);
	Json::Value* pJV = nullptr;
	for (pJV = &jv; key != 0 && pJV->isObject() == true; key = va_arg(arg, const char*)) {
	
		pJV = &(*pJV)[key];

		// vlaue 체크(for문에서는 key체크)
		if (pJV->isNull() || *pJV == "") {
			break;
		}
	}
	part.jv = *pJV;
	va_end(arg);


	return part;
}

unsigned CKlib_Json::get_count(const char* firstkey, ...)
{
	std::lock_guard<std::mutex> lock(mtx);

	va_list arg = 0;
	va_start(arg, firstkey);
	Json::Value* obj = get_obj(firstkey, arg);
	va_end(arg);

	return obj->size();
}

bool CKlib_Json::is_empty(const char* firstkey, ...)
{
	std::lock_guard<std::mutex> lock(mtx);
	
	va_list arg = 0;
	va_start(arg, firstkey);
	Json::Value* obj = get_obj(firstkey, arg);
	va_end(arg);

	return obj->empty();
}

std::string CKlib_Json::get_nth_key(const unsigned findKeyIndex, Json::Value* obj)
{
	if (obj == 0
		|| obj->isObject() == false
		|| obj->size() <= findKeyIndex) {
		return "";
	}

	Json::Value::iterator it = obj->begin();

	for (unsigned i = 0; i < findKeyIndex; ++i) {
		++it; /// std::next 또는 std::advance 함수를 쓸 경우 에러가 나서 for로 수동 증가;
	}

	return it.key().asString();
}

Json::Value* CKlib_Json::get_obj(const char* firstkey, va_list arg)
{
	const char* key = firstkey;
	Json::Value* oVal = &jv;

	while (true)
	{
		if (key == 0)
			break;

		if (oVal->isObject() == false)
			break;

		oVal = &(*oVal)[key];

		if (oVal->isNull() || *oVal == "")
			break;

		key = va_arg(arg, const char*);
	}

	return oVal;
}

Json::Value* CKlib_Json::get_nth_obj(const unsigned findKeyIndex, const char* firstkey, va_list arg)
{
	Json::Value* obj = get_obj(firstkey, arg);

	std::string key = get_nth_key(findKeyIndex, obj);

	if (key.empty())
		return 0;

	return &(*obj)[key];
}

std::string CKlib_Json::get_nth_str(const int findKeyIndex, const char* firstkey, va_list arg)
{
	if (findKeyIndex < 0
		&& firstkey == 0) {
		return "";
	}

	std::string rtn = "";

	Json::Value* pJV = nullptr;


	if (findKeyIndex < 0) {
		pJV = get_obj(firstkey, arg);
	}
	else {
		pJV = get_nth_obj(findKeyIndex, firstkey, arg);
	}

	if (pJV == nullptr) {
		return std::string();
	}


	return std::string();
}

std::string CKlib_Json::get_str(const char* firstkey, ...)
{
	std::lock_guard<std::mutex> lock(mtx);


	std::string rtn;
	va_list arg = 0;

	va_start(arg, firstkey);
	rtn = get_nth_str(-1, firstkey, arg);
	va_end(arg);


	return rtn;
}

const int CKlib_Json::get_int(const char* key, ...)
{
	std::lock_guard<std::mutex> lock(mtx);
	return 0;
}

bool CKlib_Json::set_str(const char* val, const char* key, ...)
{
	std::lock_guard<std::mutex> lock(mtx);
	return false;
}

bool CKlib_Json::ReadJsonFile(const std::string filename, Json::Value &rtnVal, std::string &errorMsg)
{
	bool rtn = false;


	try {

		HANDLE hFile = NULL;
		DWORD dwFileSize;
		DWORD dwNumberOfBytesRead;


		hFile = CreateFileA(filename.c_str(), GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			throw std::string("fopen error - invalid handle");
		}
		dwFileSize = GetFileSize(hFile, NULL);


		if (dwFileSize < 1) {
			CloseHandle(hFile);
			throw std::string("fopen error - invalid file size");
		}


		std::string str;
		str.resize(dwFileSize);


		ReadFile(hFile, &str[0], dwFileSize, &dwNumberOfBytesRead, NULL);
		CloseHandle(hFile);

		
		std::string::size_type pos = str.find_first_of('{');
		if (pos == std::string::npos) {
			throw std::string("fopen error - invalid json format");
		}


		rtnVal.clear();
		Json::Reader().parse(str.c_str() + pos, rtnVal);
	}
	catch (std::string ex) {
		errorMsg = "[shdlpKlib] Read Json FIle - Fail : ";
		errorMsg += ex;
		rtnVal.clear();
	}
	catch (std::exception ex) {
		errorMsg = "[shdlpKlib] Read Json FIle - Exception : ";
		errorMsg += ex.what();
		rtnVal.clear();
	}


	return rtn;
}

