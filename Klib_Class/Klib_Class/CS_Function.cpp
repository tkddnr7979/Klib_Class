#include "pch.h"
#include "CKlib.h"

using namespace std;


extern "C" CKLIB_DLL_API bool KLIB_FromFile(const char * filePath, char* readData, int * readSize) {

	static CKlib cklib; // mutex�� �������� �ʱ� ���� �Ϻη� �б�� klib ��ü�� ����� klib ��ü�� ����
	bool rtn = false;

	CStringA readBuffer;
	cklib.KLIB_FileDecryptAndRead(filePath, cklib.GetEncDecType(), cklib.GetEncDecLength(), readBuffer);

	if (readBuffer.GetLength() < *readSize) {
		strncpy_s(readData, (size_t)readSize, readBuffer.GetString(), (size_t)readBuffer.GetLength());
		rtn = true;
	}
	else {
		*readSize = readBuffer.GetLength() + 1;
	}

	return rtn;
}

extern "C" CKLIB_DLL_API bool KLIB_ToFile(const char* filePath, const char* data) {

	static CKlib cklib; // mutex�� �������� �ʱ� ���� �Ϻη� �б�� klib ��ü�� ����� klib ��ü�� ����

	return cklib.KLIB_FileEncryptAndSave(filePath, cklib.GetEncDecType(), cklib.GetEncDecLength(), data);;
}