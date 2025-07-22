#pragma once

#ifdef SHDLPKLIB_EXPORTS
#define CKLIB_DLL_API __declspec(dllexport)
#else
#define CKLIB_DLL_API __declspec(dllimport)
#endif

#include "klib.h"
#include <atlstr.h>
#include <vector>
#include <tuple>
#include <WtsApi32.h>
#include <mutex>

#pragma comment (lib, "wtsApi32")

class CKLIB_DLL_API CKlib
{
public:

	CKlib();
	~CKlib();

	/// <summary>
	/// shdlpchkr.exe에서 설치할 때만 사용 할 것.
	/// </summary>
	void KLIB_Init();

	void SetIntegrityFileName(CStringA fileName);
	CStringA GetKeyFilePath();
	CStringA GetIntegrityListFilePath();

	void KLIB_CheckInfo();
	void KLIB_CheckCurrentState();
	bool KLIB_ReInstall(CStringA fromWhat, CStringA reason);

	bool KLIB_FileRead(CStringA filePath, std::vector<KL_BYTE>& p_readBuffer);
	bool KLIB_FileWrite(CStringA filePath, KL_OBJECT& oData);
	//bool KLIB_FileWrite(CStringA filePath, std::vector<KL_BYTE>& p_writeBuffer);

	KLE_CONTEXT_TYPE GetEncDecType();
	KL_ULONG GetEncDecLength();
	KLE_CONTEXT_TYPE GetHashType();

	bool KLIB_KeyGenerate(KLE_CONTEXT_TYPE op_mode, KL_ULONG keylen);
	void KLIB_PrintKey(CStringA title);
	bool KLIB_SaveKey(CStringA filePath);
	bool KLIB_SetKey(std::vector<KL_BYTE>& p_readBuffer, KLE_CONTEXT_TYPE op_mode, KL_ULONG keylen);
	bool KLIB_LoadKeyFromData(CStringA data, KLE_CONTEXT_TYPE op_mode, KL_ULONG keylen);
	bool KLIB_LoadKeyFromFile(CStringA filePath, KLE_CONTEXT_TYPE op_mode, KL_ULONG keylen);

	void KLIB_ClearSensitive(KL_OBJECT_PTR p_pObject);


	// CKlib_Hash.cpp
	bool KLIB_MakeHash(KL_OBJECT& data, KLE_CONTEXT_TYPE dgst_alg, CStringA& hash);
	bool KLIB_MakeHashFromFile(CStringA filePath, KLE_CONTEXT_TYPE dgst_alg, CStringA& hash);
	bool KLIB_MakeHashFromData(CStringA data, KLE_CONTEXT_TYPE dgst_alg, CStringA& hash);


	// CKlib_Encrypt.cpp
	bool KLIB_Encrypt(KL_OBJECT* data, KL_OBJECT& oEncryptedData);
	bool KLIB_FileEncrypt(CStringA filePath, KLE_CONTEXT_TYPE op_mode, KL_ULONG keylen);	// 해당 파일을 암호화
	bool KLIB_EncryptKeyAndSaveFile(std::vector<KL_BYTE>& key, KLE_CONTEXT_TYPE op_mode, KL_ULONG keylen);
	bool KLIB_FileEncryptAndSave(CStringA filePath, KLE_CONTEXT_TYPE op_mode, KL_ULONG keylen, CStringA data); // 입력 데이터를 암호화하여 파일로 저장


	// CKilb_Decrypt.cpp
	bool KLIB_Decrypt(KL_OBJECT* data, KL_OBJECT& oDecryptedData);
	bool KLIB_FileDecrypt(CStringA filePath, KLE_CONTEXT_TYPE op_mode, KL_ULONG keylen);
	bool KLIB_FileDecryptAndRead(CStringA filePath, KLE_CONTEXT_TYPE op_mode, KL_ULONG keylen, CStringA& decryptedData);


	// CKlib_Integrity.cpp
	//bool KLIB_UpdateIntegrityList(CStringA filePath);
	bool KLIB_MakeIntegrityListFile();
	bool KLIB_IntegrityCheck();


private:

	// CKlib.cpp
	HANDLE CreateProcessWithDifferentSession(LPWSTR commandLine);
	BOOL GetActiveSessionInfo(DWORD& p_sessionId, CString& p_activeUserName);
	DWORD GetPid(CString activeUserName);
	CString GetProcessUserName(DWORD pid);

	// CKlib_Hash.cpp
	//bool KLIB_MakeHash(KL_OBJECT& data, KLE_CONTEXT_TYPE dgst_alg, CStringA& hash);

	// CKlib_Encrypt.cpp
	//bool KLIB_Encrypt(KL_OBJECT* data, KL_OBJECT& oEncryptedData);

	// CKilb_Decrypt.cpp
	//bool KLIB_Decrypt(KL_OBJECT* data, KL_OBJECT& oDecryptedData);

	// CKlib_Integrity.cpp
	CStringA KLIB_GetRegistryValueHash(HKEY regRoot, CStringA regPath, CStringA regKey);
	bool KLIB_IntegrityList_Update_FileHash();
	bool KLIB_IntegrityList_Update_RegistryHash();
	bool KLIB_RecoveryFile(CStringA p_jsnIntegrityCheckFailList);
	bool KLIB_RecoveryRegistry(CStringA p_jsnIntegrityCheckFailList);

private:
	std::mutex mtx;

	CStringA mPassWord;				// 아마 공용문서 비밀번호를 쓸 듯
	CStringA mKeyFilePath;			// key 파일 경로
	CStringA mIntegrityListFilePath;// 무결성 hash 리스트 경로

	CStringA integrityList; // 무결성 리스트

	KLE_CONTEXT_TYPE mEncDecType = KLE_CONTEXT_TYPE::KLO_CTX_ARIA_CBC_PAD;
	KL_ULONG mEncDecLength = KL_ARIA256_KEY_BYTE_LEN;
	KLE_CONTEXT_TYPE mhashType = KLE_CONTEXT_TYPE::KLO_CTX_SHA256;


	// Initialization vector : 첫 블럭을 암호화 할 때 사용되는 값 https://medium.com/%EC%8A%AC%EA%B8%B0%EB%A1%9C%EC%9A%B4-%EA%B0%9C%EB%B0%9C%EC%83%9D%ED%99%9C/%EB%B8%94%EB%A1%9D%EC%95%94%ED%98%B8-%EC%9A%B4%EC%9A%A9%EB%B0%A9%EC%8B%9D-ecb-cbc-ctr-c23875717979
	const KL_BYTE iv[16] = { 0xba,0x8c,0x2b,0x53,0xf2,0x9b,0x7f,0xd6,0xd3,0x37,0x7f,0xba,0x29,0x12,0x21,0x7d }; //Maximum IV Len : 16. Note : This buf size can be 16 or 8 according to the block cipher. 
	KL_BYTE mIV[16] = { 0x00, }; // Maximum IV Len : 16. Note : This buf size can be 16 or 8 according to the block cipher.
	
	// For Encryption / Decryption
	KL_CONTEXT mCtx = { 0, };
	KL_OBJECT mKey = { 0, };
	
	std::vector<KL_BYTE> mOrignKeyBuf, mKeyBuf;
	static const std::vector<CStringA> mIntegrityFileList;

	/// <summary>
	/// <para> CStringA : reg path </para>
	/// <para> CStringA : key ("(기본값)" == default) </para>
	/// <para> CStringA : value </para>
	/// </summary>
	static const std::vector<std::tuple<HKEY, CStringA, CStringA, CStringA>> mIntegrityList_Reg;
	static const CStringA mToken; // token : {([*])}

	static const std::vector<CStringA> mExtlist;
	//const static std::vector<std::tuple<CStringA, CStringA, CStringA>> mExtlist;
};
