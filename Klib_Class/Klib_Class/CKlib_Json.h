#pragma once
#include <json/json.h>
#include <mutex>


class CKlib_Json {

public:
	CKlib_Json();
	CKlib_Json(const CKlib_Json& other);
	CKlib_Json& operator=(const CKlib_Json& other);

	const std::string from_file(const std::string fileName);
	bool from_text(const char* text);

	const std::string to_text(const bool bFastmode = true);

	const CKlib_Json get_part(const char* key, ...);
	unsigned get_count(const char* firstkey = 0, ...); ///< ���� Ű�� ������  ��ȯ�Ѵ�.
	bool is_empty(const char* firstkey = 0, ...); ///< json �����Ͱ� ����ִ��� ������ ��ȯ�Ѵ�.

	std::string get_nth_key(const unsigned findKeyIndex, Json::Value* obj); ///< object�� n��° sub key�ش��ϴ� �ּҰ��� �����´�.

	Json::Value* get_obj(const char* firstkey, va_list arg); ///< ��� get �Լ��� �ھ����, Ű������ value�� �ּҰ��� �����´�.
	Json::Value* get_nth_obj(const unsigned findKeyIndex, const char* firstkey, va_list arg); ///< ��� get_nth �Լ��� �ھ����, Ű�� �ε����� value�� �ּҰ��� �����´�.


	std::string get_nth_str(const int findKeyIndex, const char* firstkey, va_list arg);
	std::string get_str(const char* firstkey, ...);
	const int get_int(const char* key, ...);

	bool set_str(const char* val, const char* key, ...);

private:
	Json::Value jv; ///< json root structure
	std::mutex mtx; ///< mutex for thread safety

	bool ReadJsonFile(const std::string filename, Json::Value &rtnVal, std::string &errorMsg);
	void WriteJsonFile(const Json::Value& root, const char* filename, const char** errorMsg = 0, bool bEnc = true);
};