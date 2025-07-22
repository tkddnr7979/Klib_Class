#include"pch.h"
#include "CKlib.h"
#include <string>
#include <fstream>
#include <TlHelp32.h>
#include <shdlpcurl.h>	// 에이전트 재설치용
#include "CKlib_Json.h"

//---------------------------------------------------------------------------------------------------/


CKlib::CKlib()
	: mPassWord("thisispassword")
	, mKeyFilePath("C:\\comtrue\\shdlp\\jsn\\klib_key.jsn")
{
	SetIntegrityFileName(""); // 무결성 리스트 파일 경로 default로 설정

	KLIB_Init();
}

CKlib::~CKlib()
{
	//사용 컨텍스트, 오브젝트 초기화
	K_ClearSensitive((KL_OBJECT_PTR)&mKey, 2);
	K_ClearSensitive((KL_OBJECT_PTR)&mCtx, 2);
	OutputDebugStringA("[klib] KLIB close");
}

/// <summary>
/// key 파일 생성(제거 예정)
/// key 로드
/// 
/// - 추가 개발사항
///  key 파일을 못읽을 경우 예외처리 필요.
/// </summary>
void CKlib::KLIB_Init()
{
	CStringA hash;


	if (!PathFileExistsA(mKeyFilePath)) {
		// 1. origin key 생성
		KLIB_KeyGenerate(GetEncDecType(), GetEncDecLength());
		//KLIB_PrintKey("Key Generate");
		// 1-1. 생성된 key 백업
		std::vector<KL_BYTE> generateKeyBuf = mOrignKeyBuf;

		// 2. 입력받은 비밀번호로 해쉬(32bit) 생성
		KLIB_MakeHashFromData(mPassWord, GetHashType(), hash);

		// 3. 이 해쉬를 key로 설정
		KLIB_LoadKeyFromData(hash, GetEncDecType(), GetEncDecLength());

		// 4. origin key 암호화.
		// & 5. key파일 저장
		KLIB_EncryptKeyAndSaveFile(generateKeyBuf, GetEncDecType(), GetEncDecLength());

		// 6. 다시 hash Key를 key로 설정.
		KLIB_LoadKeyFromData(hash, GetEncDecType(), GetEncDecLength());
		
		// 7. 저장된 key파일 읽고, 복호화하여 사용
		KLIB_LoadKeyFromFile(mKeyFilePath, GetEncDecType(), GetEncDecLength());
	}
	else {
		// 입력받은 비밀번호로 해쉬(32bit) 생성
		KLIB_MakeHashFromData(mPassWord, GetHashType(), hash);

		// 이 해쉬를 key로 설정
		KLIB_LoadKeyFromData(hash, GetEncDecType(), GetEncDecLength());

		// 저장된 key파일을 읽고, 내용만 (이 해쉬를 key로써) 복호화하여, 복호화된 것을 key로 사용
		KLIB_LoadKeyFromFile(mKeyFilePath, GetEncDecType(), GetEncDecLength());
	}
}

void CKlib::SetIntegrityFileName(CStringA fileName)
{
	if (fileName.GetLength() > 0
		&& CStringA(".jsn").CompareNoCase(PathFindExtensionA(fileName)) == 0) 
	{
		mIntegrityListFilePath = "C:\\comtrue\\shdlp\\jsn\\" + fileName;
	}
	else {
		mIntegrityListFilePath = "C:\\comtrue\\shdlp\\jsn\\IntegrityList.jsn";
	}
	OutputDebugStringA("[klib] set mIntegrityListFilePath : " + GetIntegrityListFilePath());
}

/// <summary>
/// update 모듈에서 동작하는 것처럼 에이전트 새로 다운 받아서 설치하도록 해야함.
/// </summary>
/// <param name="fromWhat"></param>
/// <param name="reason"></param>
bool CKlib::KLIB_ReInstall(CStringA fromWhat, CStringA reason)
{
	OutputDebugStringA("[klib] Reinstall \n - " + fromWhat + " \n - " + reason);
	bool rtn = false;
	CStringW fileName(L"shdlpRecovery.exe")
		   , downloadPath(L"c:\\comtrue\\update\\");

	try {

		CStringA modulePath;
		modulePath.GetBufferSetLength(MAX_PATH);
		GetModuleFileNameA(NULL, modulePath.GetBuffer(), modulePath.GetLength() * sizeof(char));
		PathRemoveFileSpecA(modulePath.GetBuffer());

		CKlib_Json jsnConst, jsnInfo;
		jsnConst.from_file(CStringA(modulePath + "\\jsn\\const.jsn").GetString());
		jsnInfo.from_file(CStringA(modulePath + "\\jsn\\info.jsn").GetString());


		// 무결성 리스트 파일 제거
		// -> 무결성이 맞지 않아서 재설치 하는 것이므로, 무결성 리스트 파일을 제거하고 새로 생성해야 함.
		if (PathFileExistsA(GetIntegrityListFilePath())) {
			DeleteFileA(GetIntegrityListFilePath());
		}
		// 혹시나 남아있는 이전 설치 파일 제거
		if (PathFileExistsW(downloadPath + fileName)) {
			DeleteFileW(downloadPath + fileName);
		}

		// 서버와 통신하여 에이전트 다운로드
		int retryCount = 30;
		for (retryCount; retryCount > 0; --retryCount) {

			OutputDebugStringA(CStringA("[klib] Reinstall - 에이전트 다운로드 \n - 남은 시도횟수 : ") + std::to_string(retryCount).c_str());

			int size = -1;
			int ErrCode = PostByCurl(
				jsnConst.get_str("url", "serverIp", 0).c_str()
				, jsnConst.get_int("url", "port", 0)
				, jsnConst.get_str("url", "update", 0).c_str()
				, CStringA("version=3.0.1.0000&clientId=") + jsnInfo.get_str("loginId", 0).c_str()	// 무조건 다운로드 하기위해 버전 최하위로 설정
				, &size
				, downloadPath + fileName
			);

			if (0 != ErrCode) {
				OutputDebugStringA(CStringA("[klib] Reinstall - Fail : Reinstall file download fail!! errorCode : ") + std::to_string(ErrCode).c_str());
			}
			else if (size == 0) {
				OutputDebugStringA("[klib] Reinstall - Fail : Download size is zero.");
			}
			else {
				retryCount = 10;
				break;
			}

			Sleep(500); // 0.5초 대기 후 재시도
		}


		//// 리인스톨 파일 무결성 체크
		//CStringA downloadFileHash;
		//KLIB_MakeHashFromFile(downloadPath + fileName, GetHashType(), downloadFileHash);


		// 설치파일 실행
		// -> 위에서 실패하여 retryCount가 0으로 오면 그대로 지나가도록 유도
		for (retryCount; retryCount > 0; --retryCount) {

			OutputDebugStringA(CStringA("[klib] Reinstall - 에이전트 재설치 \n - 남은 시도횟수 : ") + std::to_string(retryCount).c_str());

			// 에이전트 재설치 커맨드 실행
			if (CreateProcessWithDifferentSession((downloadPath + fileName).GetBuffer()) == INVALID_HANDLE_VALUE) {
				CStringW msg;
				msg.Format(L"[klib] Reinstall - %s 실행 실패. \n - error code : %d \n - 남은 시도횟수 : %d", fileName, GetLastError(), retryCount);
				OutputDebugStringW(msg);
				Sleep(500); // 0.5초 대기 후 재시도
				continue;
			}

			OutputDebugStringA("[klib] Reinstall - " + CStringA(fileName + " 실행 성공"));
			break;
		}


		rtn = true;
	}
	catch (CStringA msg) {
		OutputDebugStringA("[klib] Reinstall - Fail : " + msg);
		rtn = false; 
	}
	catch (std::exception ex) {
		OutputDebugStringA(CStringA("[klib] Reinstall - Exception : ") + ex.what());
		rtn = false;
	}


	return rtn;
}

CStringA CKlib::GetKeyFilePath()
{
	return mKeyFilePath;
}

CStringA CKlib::GetIntegrityListFilePath()
{
	return mIntegrityListFilePath;
}

void CKlib::KLIB_CheckInfo()
{

	KL_INFO klibInfo;
	KL_RV ret = K_GetInfo(&klibInfo);

	CStringA msg;
	msg.AppendFormat("[klib] %s V%d.%d\n"
		, klibInfo.libraryDescription
		, klibInfo.libraryVersion.major
		, klibInfo.libraryVersion.minor);
	msg.AppendFormat("[klib] Error Msg : %s\n", K_GetErrorMsg(ret));
	OutputDebugStringA(msg);
}

void CKlib::KLIB_CheckCurrentState()
{
	CStringA msg;

	KL_INFO klibInfo;

	K_CurrState(&klibInfo);

	switch (klibInfo.klib_mod_stat)
	{
	case KLS_MODULE_LOADED:			msg.Append("[klib] state : [KLS_MODULE_LOADED]\n");			break;
	case KLS_MODULE_DISAPPROVAL:	msg.Append("[klib] state : [KLS_MODULE_DISAPPROVAL]\n");	break;
	case KLS_MODULE_APPROVAL:		msg.Append("[klib] state : [KLS_MODULE_APPROVAL]\n");		break;
	case KLS_MODULE_FATAL_ERROR:	msg.Append("[klib] state : [KLS_MODULE_FATAL_ERROR]\n");	break;
	case KLS_MODULE_TERMINATE:		msg.Append("[klib] state : [KLS_MODULE_TERMINATE]\n");		break;
	case KLS_MODULE_SELFTEST:		msg.Append("[klib] state : [KLS_MODULE_SELFTEST]\n");		break;
	}


	msg.AppendFormat("[klib] KLS_ARIA      : %s\n", (klibInfo.kalginfo.KLS_ARIA_ALG == KLS_ALG_NOT_INITIALIZED) ? "not initialized" : "has been initialized");
	msg.AppendFormat("[klib] KLS_SEED      : %s\n", (klibInfo.kalginfo.KLS_SEED_ALG == KLS_ALG_NOT_INITIALIZED) ? "not initialized" : "has been initialized");
	msg.AppendFormat("[klib] KLS_LEA       : %s\n", (klibInfo.kalginfo.KLS_LEA_ALG == KLS_ALG_NOT_INITIALIZED) ? "not initialized" : "has been initialized");
	msg.AppendFormat("[klib] KLS_HIGHT     : %s\n", (klibInfo.kalginfo.KLS_HIGHT_ALG == KLS_ALG_NOT_INITIALIZED) ? "not initialized" : "has been initialized");

	msg.AppendFormat("[klib] KLS_SHA2      : %s\n", (klibInfo.kalginfo.KLS_SHA2_ALG == KLS_ALG_NOT_INITIALIZED) ? "not initialized" : "has been initialized");

	msg.AppendFormat("[klib] KLS_ARIA_MAC  : %s\n", (klibInfo.kalginfo.KLS_ARIA_MAC_ALG == KLS_ALG_NOT_INITIALIZED) ? "not initialized" : "has been initialized");
	msg.AppendFormat("[klib] KLS_SEED_MAC  : %s\n", (klibInfo.kalginfo.KLS_SEED_MAC_ALG == KLS_ALG_NOT_INITIALIZED) ? "not initialized" : "has been initialized");
	msg.AppendFormat("[klib] KLS_LEA_MAC   : %s\n", (klibInfo.kalginfo.KLS_LEA_MAC_ALG == KLS_ALG_NOT_INITIALIZED) ? "not initialized" : "has been initialized");
	msg.AppendFormat("[klib] KLS_HIGHT_MAC : %s\n", (klibInfo.kalginfo.KLS_HIGHT_MAC_ALG == KLS_ALG_NOT_INITIALIZED) ? "not initialized" : "has been initialized");

	msg.AppendFormat("[klib] KLS_SHA2_MAC  : %s\n", (klibInfo.kalginfo.KLS_SHA2_MAC_ALG == KLS_ALG_NOT_INITIALIZED) ? "not initialized" : "has been initialized");

	msg.AppendFormat("[klib] KLS_DRBG      : %s\n", (klibInfo.kalginfo.KLS_DRBG_ALG == KLS_ALG_NOT_INITIALIZED) ? "not initialized" : "has been initialized");

	msg.AppendFormat("[klib] KLS_RSAES     : %s\n", (klibInfo.kalginfo.KLS_RSAES_ALG == KLS_ALG_NOT_INITIALIZED) ? "not initialized" : "has been initialized");

	msg.AppendFormat("[klib] KLS_RSAPSS    : %s\n", (klibInfo.kalginfo.KLS_RSAPSS_ALG == KLS_ALG_NOT_INITIALIZED) ? "not initialized" : "has been initialized");

	msg.AppendFormat("[klib] KLS_ECDSA     : %s\n", (klibInfo.kalginfo.KLS_ECDSA_ALG == KLS_ALG_NOT_INITIALIZED) ? "not initialized" : "has been initialized");
	msg.AppendFormat("[klib] KLS_EC_KCDSA  : %s\n", (klibInfo.kalginfo.KLS_EC_KCDSA_ALG == KLS_ALG_NOT_INITIALIZED) ? "not initialized" : "has been initialized");
	msg.AppendFormat("[klib] KLS_KCDSA     : %s\n", (klibInfo.kalginfo.KLS_KCDSA_ALG == KLS_ALG_NOT_INITIALIZED) ? "not initialized" : "has been initialized");

	msg.AppendFormat("[klib] KLS_ECDH      : %s\n", (klibInfo.kalginfo.KLS_ECDH_ALG == KLS_ALG_NOT_INITIALIZED) ? "not initialized" : "has been initialized");

	OutputDebugStringA(msg);
}

bool CKlib::KLIB_FileRead(CStringA filePath, std::vector<KL_BYTE>& p_readBuffer) {

	bool rtn = false;


	if (!PathFileExistsA(filePath)) {
		OutputDebugStringA("[klib] KLIB_FileRead - Fail : File not found \n\t - file : " + filePath);
		return rtn;
	}


	//OutputDebugStringA(CStringA("[klib] KLIB_FileRead - file open : ") + filePath);
	std::ifstream fileStream(filePath, std::ios::in | std::ios::binary);
	if (!fileStream.is_open()) {
		OutputDebugStringA("[klib] KLIB_FileRead - Fail : File can not open \n\t - file : " + filePath);
		return rtn;
	}
	
	
	try {
		p_readBuffer.assign(std::istreambuf_iterator<char>(fileStream), std::istreambuf_iterator<char>());
	
		rtn = true;
	}
	catch (std::exception ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_FileRead - Exception : ") + ex.what());
		rtn = false;
	}
	
	if (fileStream.is_open()) {
		//OutputDebugStringA(CStringA("[klib] KLIB_FileRead - file close : ") + filePath);
		fileStream.close();
	}

	//FILE* readFile = nullptr;
	//
	//try {
	//	int errorCode = fopen_s(&readFile, filePath, "rb");
	//	if (errorCode != 0 || readFile == nullptr) {
	//		throw CStringA("[klib] KLIB_FileRead - Fail : File not open (GetLastError : ") + std::to_string(GetLastError()).c_str() + ")";
	//	}
	//
	//
	//	// 파일 크기 구하기
	//	OutputDebugStringA(CStringA("[klib] KLIB_FileRead - file read : ") + filePath);
	//	fseek(readFile, 0, SEEK_END);
	//	size_t fileSize = ftell(readFile);
	//	fseek(readFile, 0, SEEK_SET);
	//	p_readBuffer.resize(fileSize);
	//
	//	// 파일 내용 읽기
	//	//fread(p_readBuffer.data(), sizeof(KL_BYTE), fileSize, readFile);
	//	fread_s(p_readBuffer.data(), fileSize, sizeof(KL_BYTE), fileSize, readFile);
	//
	//
	//	rtn = true;
	//}
	//catch (CStringA ex) {
	//	OutputDebugStringA(CStringA("[klib] KLIB_FileRead - Fail : ") + ex);
	//	rtn = false;
	//}
	//
	//
	//if (readFile != nullptr) {
	//	OutputDebugStringA(CStringA("[klib] KLIB_FileRead - file close : ") + filePath);
	//	fclose(readFile);
	//}


	return rtn;
}

bool CKlib::KLIB_FileWrite(CStringA filePath, KL_OBJECT& oData)
{
	bool rtn = false;

	
	std::ofstream writeStream;
	
	
	try {
		// 파일 열기
		// trunc를 쓰면 이상하게 임시폴더에서는 파일을 못 엶.
		//  -> 자동복호화한 파일을 닫을 때 암호화 하려는 파일이 임시폴더에 생성됨.
		//  -> 이 건은 shdenc에서 동작하도록 개조하는 것으로 해결함.
		// trunc를 사용하지 않으면 key파일을 생성하지 못함.
		//  -> 추후에는 에이전트가 자체적으로 key파일 생성하지 않도록 하기로해서 이건 넘어갈수 있을 것 같음
		//OutputDebugStringA(CStringA("[klib] KLIB_FileWrite - file open : ") + filePath);
		writeStream.open(filePath, std::ios::in | std::ios::out | std::ios::binary | std::ios::trunc);
	
		// 파일이 열리지 않으면 예외
		//OutputDebugStringA(CStringA("[klib] KLIB_FileWrite - file open check : ") + filePath);
		if (!writeStream.is_open()) {
			CStringA errMsg;
			errMsg.Format("File not found (GetLastError : %d)", GetLastError());
			throw errMsg;
		}
	
		// 암호화된 데이터를 파일에 씀
		//OutputDebugStringA(CStringA("[klib] KLIB_FileWrite - file write : ") + filePath);
		writeStream.write(reinterpret_cast<const char*>(oData[1].pValue), oData[1].ulValueLen);
	
	
		rtn = true;
	}
	catch (CStringA ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_FileWrite - Fail : ") + ex);
		rtn = false;
	}
	
	
	// 파일 닫기
	if (writeStream.is_open()) {
		//OutputDebugStringA(CStringA("[klib] KLIB_FileWrite - file close : ") + filePath);
		writeStream.close();
	}

	//FILE* writeFile = nullptr;
	//
	//try {
	//	
	//	int errorCode = fopen_s(&writeFile, filePath, "w+b");
	//
	//	if (errorCode != 0 || writeFile == nullptr) {
	//		throw CStringA("[klib] KLIB_FileWrite - Fail : File not open (GetLastError : ") + std::to_string(GetLastError()).c_str() + ")";
	//	}
	//
	//	OutputDebugStringA(CStringA("[klib] KLIB_FileWrite - file write : ") + filePath);
	//	//outputFile.write(reinterpret_cast<const char*>(oData[1].pValue), oData[1].ulValueLen);
	//
	//	//fprintf_s(writeFile, "%s", reinterpret_cast<const char*>(oData[1].pValue));
	//	fwrite(oData[1].pValue, sizeof(KL_BYTE), oData[1].ulValueLen, writeFile);
	//
	//	rtn = true;
	//}
	//catch (CStringA ex) {
	//	OutputDebugStringA(CStringA("[klib] KLIB_FileWrite - Fail : ") + ex);
	//	rtn = false;
	//}
	//
	//
	//if (writeFile != nullptr) {
	//	OutputDebugStringA(CStringA("[klib] KLIB_FileWrite - file close : ") + filePath);
	//	fclose(writeFile);
	//}

	return rtn;
}

KLE_CONTEXT_TYPE CKlib::GetEncDecType()
{
	return mEncDecType;
}

KL_ULONG CKlib::GetEncDecLength()
{
	return mEncDecLength;
}

KLE_CONTEXT_TYPE CKlib::GetHashType()
{
	return mhashType;
}

/// <summary>
/// 새로운 key 생성하여 mOrignKeyBuf, mKeyBuf, mKey, mCtx에 값을 설정함.
/// </summary>
/// <param name="op_mode"></param>
/// <param name="keylen"></param>
/// <returns></returns>
bool CKlib::KLIB_KeyGenerate(KLE_CONTEXT_TYPE op_mode, KL_ULONG keylen)
{
	bool rtn = false;


	//keygeneration
	KL_CONTEXT keygenctx = {
		{ KLO_CTX_SYM_KEY_GEN, NULL, 0, FALSE, FALSE },
	};
	KL_BYTE secretKeyBuf[32] = { 0x00, }; //Maximum Key Len : 32. Note : This buf size can be 16, 24 or 32 according to the block cipher. 
	mKey[0] = { KLO_SECRET_KEY, NULL, 0, FALSE, FALSE };
	mKey[1] = { KLA_VALUE, (KL_VOID_PTR)secretKeyBuf, 0, TRUE, FALSE };

	//For Encryption/Decryption
	memset(mIV, 0x00, sizeof(mIV));
	memcpy_s(mIV, sizeof(mIV), iv, sizeof(iv));
	mCtx[0] = { (KL_ULONG)op_mode, NULL, 0, FALSE, FALSE };
	mCtx[1] = { KLA_BLOCK_IV, mIV, 0, FALSE, FALSE };


	try {

		KL_RV ret;
		CStringA msg;

		//Step1 - 파라미터 설정
		switch (op_mode)
		{
			/*ARIA*/
		case KLO_CTX_ARIA_CBC:
		case KLO_CTX_ARIA_CBC_PAD:
		case KLO_CTX_ARIA_OFB:
		case KLO_CTX_ARIA_CFB:
		case KLO_CTX_ARIA_CTR:
		case KLO_CTX_ARIA_CTR_PAD:
			mCtx[1].type = KLA_BLOCK_IV;
			mCtx[1].ulValueLen = KL_ARIA_BLOCK_BYTE_LEN;	//IV  Len : must be the same as the block size
		case KLO_CTX_ARIA_ECB:								//Note : ECB does note require IV
		case KLO_CTX_ARIA_ECB_PAD:
			mKey[1].ulValueLen = keylen;					//Key Len : This chooses one of versions(ARIA128, ARIA192, ARIA256)
			break;

			/*SEED*/
		case KLO_CTX_SEED_CBC:
		case KLO_CTX_SEED_CBC_PAD:
		case KLO_CTX_SEED_OFB:
		case KLO_CTX_SEED_CFB:
		case KLO_CTX_SEED_CTR:
		case KLO_CTX_SEED_CTR_PAD:
			mCtx[1].type = KLA_BLOCK_IV;
			mCtx[1].ulValueLen = KL_SEED_BLOCK_BYTE_LEN;	//IV  Len : must be the same as the block size
		case KLO_CTX_SEED_ECB:								//Note : ECB does note require IV
		case KLO_CTX_SEED_ECB_PAD:
			mKey[1].ulValueLen = keylen;					//Key Len : There is only one version of SEED with keylen = 16
			break;

			/*LEA*/
		case KLO_CTX_LEA_CBC:
		case KLO_CTX_LEA_CBC_PAD:
		case KLO_CTX_LEA_OFB:
		case KLO_CTX_LEA_CFB:
		case KLO_CTX_LEA_CTR:
		case KLO_CTX_LEA_CTR_PAD:
			mCtx[1].type = KLA_BLOCK_IV;
			mCtx[1].ulValueLen = KL_LEA_BLOCK_BYTE_LEN;	//IV  Len : must be the same as the block size
		case KLO_CTX_LEA_ECB:								//Note : ECB does note require IV
		case KLO_CTX_LEA_ECB_PAD:
			mKey[1].ulValueLen = keylen;					//Key Len : This chooses one of versions(LEA128, LEA192, LEA256)
			break;

			/*HIGHT*/
		case KLO_CTX_HIGHT_CBC:
		case KLO_CTX_HIGHT_CBC_PAD:
		case KLO_CTX_HIGHT_OFB:
		case KLO_CTX_HIGHT_CFB:
		case KLO_CTX_HIGHT_CTR:
		case KLO_CTX_HIGHT_CTR_PAD:
			mCtx[1].type = KLA_BLOCK_IV;
			mCtx[1].ulValueLen = KL_HIGHT_BLOCK_BYTE_LEN;	//IV  Len : must be the same as the block size
		case KLO_CTX_HIGHT_ECB:								//Note : ECB does note require IV
		case KLO_CTX_HIGHT_ECB_PAD:
			mKey[1].ulValueLen = keylen;					//Key Len : There is only one version of HIGHT with keylen = 8
			break;

			/*AES*/
		case KLO_CTX_AES_CBC:
		case KLO_CTX_AES_CBC_PAD:
		case KLO_CTX_AES_OFB:
		case KLO_CTX_AES_CFB:
		case KLO_CTX_AES_CTR:
		case KLO_CTX_AES_CTR_PAD:
			mCtx[1].type = KLA_BLOCK_IV;
			mCtx[1].ulValueLen = KL_AES_BLOCK_BYTE_LEN;	//IV  Len : must be the same as the block size
		case KLO_CTX_AES_ECB:								//Note : ECB does note require IV
		case KLO_CTX_AES_ECB_PAD:
			mKey[1].ulValueLen = keylen;					//Key Len : This chooses one of versions(AES128, AES192, AES256)
			break;

			/*TDES*/
		case KLO_CTX_TDES_CBC:
		case KLO_CTX_TDES_CBC_PAD:
		case KLO_CTX_TDES_OFB:
		case KLO_CTX_TDES_CFB:
		case KLO_CTX_TDES_CTR:
		case KLO_CTX_TDES_CTR_PAD:
			mCtx[1].type = KLA_BLOCK_IV;
			mCtx[1].ulValueLen = KL_TDES_BLOCK_BYTE_LEN;	//IV  Len : must be the same as the block size
		case KLO_CTX_TDES_ECB:								//Note : ECB does note require IV
		case KLO_CTX_TDES_ECB_PAD:
			mKey[1].ulValueLen = keylen;					//Key Len : There is only one version of TDES with keylen = 16 (Only 2key-mode is supported)
			break;

		default:
			throw CStringA("Algorithm Not Supported.\n");
		}

		//Step 2 - 키생성 : K_GenerateKey
		//// oKey에 키를 직접 넣어주어도된다. 
		if ((ret = K_GenerateKey(&keygenctx, (KL_OBJECT_PTR)&mKey)) != KLR_OK) {
			CStringA msg;
			msg.Format("K_GenerateKey failed: %s\n", K_GetErrorMsg(ret));
			throw msg;
		}
		

		// 생성된 key를 멤버변수에 저장
		CStringA generatedKey;
		KL_CHAR_PTR pStart = (KL_CHAR_PTR)mKey[1].pValue
					, pEnd = pStart + mKey[1].ulValueLen;

		for (KL_CHAR_PTR pPointer = pStart; pPointer < pEnd; ++pPointer) {
			generatedKey.AppendFormat("%02x", *pPointer);
		}
		KLIB_LoadKeyFromData(generatedKey, op_mode, keylen);


		//K_HexDump((KL_BYTE_PTR)mKey[1].pValue, mKey[1].ulValueLen, (KL_BYTE_PTR)"KLIB_KeyGenerate - mKey");
		//KLIB_PrintKey("Key Generate");

		rtn = true;
	}
	catch (CStringA ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_KeyGenerate - Fail : ") + ex);
		rtn = false;
	}


	return rtn;
}

void CKlib::KLIB_PrintKey(CStringA title)
{
	CStringA csMsg;
	csMsg.Format("--[%s]------------------------------------------------", title.GetString());
	OutputDebugStringA(csMsg);

	// 값 확인 - mCtx
	if (mCtx[1].ulValueLen != 0) {
		//K_HexDump((KL_BYTE_PTR)mCtx[1].pValue, mCtx[1].ulValueLen, (KL_BYTE_PTR)"mCtx - iv");

		CStringA csCtx;
		KL_CHAR_PTR pStart = (KL_CHAR_PTR)mCtx[1].pValue;
		KL_CHAR_PTR pEnd = pStart + mCtx[1].ulValueLen;
		
		for (KL_CHAR_PTR pPointer = pStart; pPointer < pEnd; ++pPointer) {
			csCtx.AppendFormat("%02x", *pPointer);
		}
		OutputDebugStringA(csCtx);
	}

	// 값 확인 - mKey
	//K_HexDump((KL_BYTE_PTR)mKey[1].pValue, mKey[1].ulValueLen, (KL_BYTE_PTR)"mKey");
	CStringA csKey;
	KL_CHAR_PTR pStart = (KL_CHAR_PTR)mKey[1].pValue;
	KL_CHAR_PTR pEnd = pStart + mKey[1].ulValueLen;

	for (KL_CHAR_PTR pPointer = pStart; pPointer < pEnd; ++pPointer) {
		csKey.AppendFormat("%02x", *pPointer);
	}
	OutputDebugStringA(csKey);
}

bool CKlib::KLIB_SaveKey(CStringA filePath)
{
	KL_OBJECT mOrignKey = {
		{ KLO_SECRET_KEY, NULL, 0, FALSE, FALSE },
		{ KLA_VALUE, mOrignKeyBuf.data(), mOrignKeyBuf.size(), TRUE, FALSE}
	};
	return KLIB_FileWrite(filePath, mOrignKey);
}

bool CKlib::KLIB_SetKey(std::vector<KL_BYTE>& p_readBuffer, KLE_CONTEXT_TYPE op_mode, KL_ULONG keylen)
{
	bool rtn = false;

	//For Data(Plaintext or Ciphertext)
	mKey[0] = { KLO_SECRET_KEY, NULL, 0, FALSE, FALSE };
	mKey[1] = { KLA_VALUE, p_readBuffer.data(), (KL_ULONG)p_readBuffer.size(), TRUE, FALSE };

	//For Encryption/Decryption
	memset(mIV, 0x00, sizeof(mIV));
	memcpy_s(mIV, sizeof(mIV), iv, sizeof(iv));
	mCtx[0] = { (KL_ULONG)op_mode, NULL, 0, FALSE, FALSE };
	mCtx[1] = { KLA_BLOCK_IV, mIV, 0, FALSE, FALSE };


	try {

		KL_RV ret;
		CStringA msg;

		//Step1 - 파라미터 설정
		switch (op_mode)
		{
			/*ARIA*/
		case KLO_CTX_ARIA_CBC:
		case KLO_CTX_ARIA_CBC_PAD:
		case KLO_CTX_ARIA_OFB:
		case KLO_CTX_ARIA_CFB:
		case KLO_CTX_ARIA_CTR:
		case KLO_CTX_ARIA_CTR_PAD:
			mCtx[1].type = KLA_BLOCK_IV;
			mCtx[1].ulValueLen = KL_ARIA_BLOCK_BYTE_LEN;	//IV  Len : must be the same as the block size
		case KLO_CTX_ARIA_ECB:								//Note : ECB does note require IV
		case KLO_CTX_ARIA_ECB_PAD:
			mKey[1].ulValueLen = keylen;					//Key Len : This chooses one of versions(ARIA128, ARIA192, ARIA256)
			break;

			/*SEED*/
		case KLO_CTX_SEED_CBC:
		case KLO_CTX_SEED_CBC_PAD:
		case KLO_CTX_SEED_OFB:
		case KLO_CTX_SEED_CFB:
		case KLO_CTX_SEED_CTR:
		case KLO_CTX_SEED_CTR_PAD:
			mCtx[1].type = KLA_BLOCK_IV;
			mCtx[1].ulValueLen = KL_SEED_BLOCK_BYTE_LEN;	//IV  Len : must be the same as the block size
		case KLO_CTX_SEED_ECB:								//Note : ECB does note require IV
		case KLO_CTX_SEED_ECB_PAD:
			mKey[1].ulValueLen = keylen;					//Key Len : There is only one version of SEED with keylen = 16
			break;

			/*LEA*/
		case KLO_CTX_LEA_CBC:
		case KLO_CTX_LEA_CBC_PAD:
		case KLO_CTX_LEA_OFB:
		case KLO_CTX_LEA_CFB:
		case KLO_CTX_LEA_CTR:
		case KLO_CTX_LEA_CTR_PAD:
			mCtx[1].type = KLA_BLOCK_IV;
			mCtx[1].ulValueLen = KL_LEA_BLOCK_BYTE_LEN;	//IV  Len : must be the same as the block size
		case KLO_CTX_LEA_ECB:								//Note : ECB does note require IV
		case KLO_CTX_LEA_ECB_PAD:
			mKey[1].ulValueLen = keylen;					//Key Len : This chooses one of versions(LEA128, LEA192, LEA256)
			break;

			/*HIGHT*/
		case KLO_CTX_HIGHT_CBC:
		case KLO_CTX_HIGHT_CBC_PAD:
		case KLO_CTX_HIGHT_OFB:
		case KLO_CTX_HIGHT_CFB:
		case KLO_CTX_HIGHT_CTR:
		case KLO_CTX_HIGHT_CTR_PAD:
			mCtx[1].type = KLA_BLOCK_IV;
			mCtx[1].ulValueLen = KL_HIGHT_BLOCK_BYTE_LEN;	//IV  Len : must be the same as the block size
		case KLO_CTX_HIGHT_ECB:								//Note : ECB does note require IV
		case KLO_CTX_HIGHT_ECB_PAD:
			mKey[1].ulValueLen = keylen;					//Key Len : There is only one version of HIGHT with keylen = 8
			break;

			/*AES*/
		case KLO_CTX_AES_CBC:
		case KLO_CTX_AES_CBC_PAD:
		case KLO_CTX_AES_OFB:
		case KLO_CTX_AES_CFB:
		case KLO_CTX_AES_CTR:
		case KLO_CTX_AES_CTR_PAD:
			mCtx[1].type = KLA_BLOCK_IV;
			mCtx[1].ulValueLen = KL_AES_BLOCK_BYTE_LEN;	//IV  Len : must be the same as the block size
		case KLO_CTX_AES_ECB:								//Note : ECB does note require IV
		case KLO_CTX_AES_ECB_PAD:
			mKey[1].ulValueLen = keylen;					//Key Len : This chooses one of versions(AES128, AES192, AES256)
			break;

			/*TDES*/
		case KLO_CTX_TDES_CBC:
		case KLO_CTX_TDES_CBC_PAD:
		case KLO_CTX_TDES_OFB:
		case KLO_CTX_TDES_CFB:
		case KLO_CTX_TDES_CTR:
		case KLO_CTX_TDES_CTR_PAD:
			mCtx[1].type = KLA_BLOCK_IV;
			mCtx[1].ulValueLen = KL_TDES_BLOCK_BYTE_LEN;	//IV  Len : must be the same as the block size
		case KLO_CTX_TDES_ECB:								//Note : ECB does note require IV
		case KLO_CTX_TDES_ECB_PAD:
			mKey[1].ulValueLen = keylen;					//Key Len : There is only one version of TDES with keylen = 16 (Only 2key-mode is supported)
			break;

		default:
			throw CStringA("Algorithm Not Supported.\n");
		}

		rtn = true;
	}
	catch (CStringA ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_LoadKey - Fail : ") + ex);
		rtn = false;
	}


	return rtn;
}

bool CKlib::KLIB_LoadKeyFromData(CStringA data, KLE_CONTEXT_TYPE op_mode, KL_ULONG keylen)
{
	bool rtn = false;

	mOrignKeyBuf.clear();

	// string to hexa
	for (int idx = 0; idx < data.GetLength(); idx += 2) {
		mOrignKeyBuf.push_back(static_cast<KL_BYTE>(strtoul(data.Mid(idx, 2), nullptr, 16)));
	}

	mKeyBuf.clear();
	mKeyBuf = mOrignKeyBuf;
	return KLIB_SetKey(mKeyBuf, op_mode, keylen);
}

bool CKlib::KLIB_LoadKeyFromFile(CStringA filePath, KLE_CONTEXT_TYPE op_mode, KL_ULONG keylen)
{
	bool rtn = false;
	CStringA msg;


	//--[File Open]-------------------------------------------------------------------------//

	std::vector<KL_BYTE> readData;
	if (KLIB_FileRead(filePath, readData) == false) {
		OutputDebugStringA("[klib] KLIB_LoadKeyFromFile - Fail : File not found");
		return false;
	}


	//--[Init]-------------------------------------------------------------------------//
	
	//For Data(Plaintext or Ciphertext)
	KL_OBJECT oData = {
		{KLO_DATA, NULL, 0, FALSE, FALSE},
		{KLA_VALUE, readData.data(), readData.size(), TRUE, FALSE},
	};

	//For Encryption Output
	KL_BYTE_PTR EncDataBuf = NULL;
	KL_OBJECT oEncryptedData = {
		{KLO_DATA,	NULL, 0, FALSE, FALSE},
		{KLA_VALUE, EncDataBuf, 0, FALSE, FALSE}
	};

	//For Decryption Output
	KL_BYTE_PTR DecDataBuf = NULL;
	KL_OBJECT oDecryptedData = {
		{KLO_DATA,	NULL, 0, FALSE, FALSE},
		{KLA_VALUE, DecDataBuf, 0, FALSE, FALSE}
	};


	try {

		KL_RV ret;


		//--[Decrypt]-------------------------------------------------------------------------//

		if (!KLIB_Decrypt(&oData, oDecryptedData)) {
			msg.Format("Decrpyt failed \n");
			throw msg;
		}
		//K_HexDump((KL_BYTE_PTR)oDecryptedData[1].pValue, oDecryptedData[1].ulValueLen, (KL_BYTE_PTR)"decrypted key from File");


		//--[Decrypt 무결성 체크]-------------------------------------------------------------------------//

		if (!KLIB_Encrypt(&oDecryptedData, oEncryptedData)) {
			msg.Format("Decrpyt Check - Encrpyt failed \n");
			throw msg;
		}


		// 해쉬값 비교
		CStringA hashOrigin, hashCopy;
		KLIB_MakeHash(oData, GetHashType(), hashOrigin);
		KLIB_MakeHash(oEncryptedData, GetHashType(), hashCopy);
		bool bHashCompare = (hashOrigin.CompareNoCase(hashCopy) == 0)
							&& hashOrigin.GetLength() > 0
							&& hashCopy.GetLength() > 0;
		//OutputDebugStringA(CStringA("[klib] KLIB_FileDecrypt - Hash compare : ") + (bHashCompare ? "True" : "False"));
		if (!bHashCompare) {
			throw CStringA("Decrpyt Check - Compare failed");
		}


		//--[key Update]-------------------------------------------------------------------------//

		// 복호화 결과 정리 : 여기서 선언한 복호화 변수를 그대로 사용하면, 함수 나가는 순간 버퍼가 사라져 key가 날아가니 주의
		CStringA decKey;
		KL_CHAR_PTR pStart = (KL_CHAR_PTR)oDecryptedData[1].pValue
					, pEnd = pStart + oDecryptedData[1].ulValueLen;
		for (KL_CHAR_PTR pPointer = pStart; pPointer < pEnd; ++pPointer) {
			decKey.AppendFormat("%02x", *pPointer);
		}

		// key값 갱신
		rtn = KLIB_LoadKeyFromData(decKey, op_mode, keylen);
	}
	catch (CStringA ex) {
		OutputDebugStringA(CStringA("[klib] KLIB_LoadKeyFromFile - Fail : ") + ex);
		rtn = false;
	}


	//--[Release]-------------------------------------------------------------------------//

	//사용 컨텍스트, 오브젝트 초기화
	K_ClearSensitive((KL_OBJECT_PTR)&oData, 2);
	K_ClearSensitive((KL_OBJECT_PTR)&oEncryptedData, 2);
	K_ClearSensitive((KL_OBJECT_PTR)&oDecryptedData, 2);

	if (oEncryptedData[1].pValue != NULL) {
		free(oEncryptedData[1].pValue);
	}
	if (oDecryptedData[1].pValue != NULL) {
		free(oDecryptedData[1].pValue);
	}

	return rtn;
}

void CKlib::KLIB_ClearSensitive(KL_OBJECT_PTR p_pObject)
{
	K_ClearSensitive(p_pObject, 2);;
}


HANDLE CKlib::CreateProcessWithDifferentSession(LPWSTR commandLine)
{
	DWORD dwSessionId;
	CString activeUserName;
	GetActiveSessionInfo(dwSessionId, activeUserName);
	
	DWORD winlogonPid = GetPid(activeUserName);

	if (winlogonPid == 0) {
		return INVALID_HANDLE_VALUE;
	}
	// 해당 세션의 유저 토큰을 가져온다
	HANDLE hUserToken = NULL;
	WTSQueryUserToken(dwSessionId, &hUserToken);

	HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, winlogonPid);
	HANDLE hPToken = NULL;
	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID | TOKEN_READ | TOKEN_WRITE, &hPToken) == 0) {
		CloseHandle(hUserToken);
		return INVALID_HANDLE_VALUE;
	}



	return HANDLE();
}


BOOL CKlib::GetActiveSessionInfo(DWORD &p_sessionId, CString &p_activeUserName)
{
	BOOL rtn = FALSE;
	PWTS_SESSION_INFO ppSessionInfo = NULL;
	DWORD pCount = 0;

	// 세션 리스트 취득
	if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &ppSessionInfo, &pCount))
	{
		for (DWORD idx = 0; idx < pCount; ++idx)
		{
			// 현재 활성화된 세션정보를 취득
			WTS_SESSION_INFO sessionInfo = ppSessionInfo[idx];
			if (sessionInfo.State == WTSActive)
			{
				LPTSTR ppBuffer = 0;
				DWORD pBytesReturned = 0;

				if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, sessionInfo.SessionId, WTS_INFO_CLASS::WTSUserName, &ppBuffer, &pBytesReturned))
				{
					p_sessionId = sessionInfo.SessionId;
					p_activeUserName = ppBuffer;

					WTSFreeMemory(ppBuffer); // WTSQuerySessionInformation

					rtn = TRUE;
					break;
				}
			}
		}

		WTSFreeMemory(ppSessionInfo); // WTSEnumerateSessions
	}

	return rtn;
}

DWORD CKlib::GetPid(CString activeUserName)
{
	enum Type
	{
		SYSTEM = 0,
		USER
	};
	static LPCWSTR processNames[]{ L"winlogon.exe", L"explorer.exe" };

	DWORD pid = -1;

	CString processName = processNames[Type::SYSTEM];

	HANDLE hProcess = NULL;
	PROCESSENTRY32 pe32 = { sizeof pe32 };

	hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcess != INVALID_HANDLE_VALUE)
	{
		if (Process32First(hProcess, &pe32))
		{
			do
			{
				if (processName.CompareNoCase(pe32.szExeFile) == 0)
				{
					pid = pe32.th32ProcessID;

					if (activeUserName.CompareNoCase(GetProcessUserName(pid)) == 0)
					{
						break;
					}
				}
			} while (Process32Next(hProcess, &pe32));
		}

		CloseHandle(hProcess);
	}

	return pid;
}

CString CKlib::GetProcessUserName(DWORD pid)
{
	CString userName = _T("");

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (hProcess != NULL)
	{
		HANDLE hToken = NULL;
		if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
		{
			DWORD length;
			GetTokenInformation(hToken, TokenUser, NULL, 0, &length);

			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				PTOKEN_USER pTokenUser = (PTOKEN_USER)new byte[length];

				if (pTokenUser != NULL)
				{
					if (GetTokenInformation(hToken, TokenUser, (LPVOID)pTokenUser, length, &length))
					{
						SID_NAME_USE sid;
						TCHAR name[MAX_PATH];
						DWORD nameLength = MAX_PATH;
						TCHAR domain[MAX_PATH];
						DWORD domainLength = MAX_PATH;

						if (LookupAccountSid(NULL, pTokenUser->User.Sid, name, &nameLength, domain, &domainLength, &sid))
						{
							userName = name;
						}
					}
					delete pTokenUser;
				}
			}
			CloseHandle(hToken);
		}
		CloseHandle(hProcess);
	}

	return userName;
}