#include <iostream>
#include "CKlib.h"
#include "klib.h"

using namespace std;

int main() {
	CKlib klib;


	//bool bRst = klib.KLIB_FileDecrypt("D:\\clientInfo.jsn", klib.GetEncDecType(), klib.GetEncDecLength());
	bool bRst = klib.KLIB_FileDecrypt("D:\\test.jsn", klib.GetEncDecType(), klib.GetEncDecLength());
	//bool bRst = klib.KLIB_FileDecrypt("D:\\info.jsn", klib.GetEncDecType(), klib.GetEncDecLength());

	cout << "KLIB_FileDecrypt result: " << (bRst ? "Success" : "Failure") << endl;

	return 0;
}