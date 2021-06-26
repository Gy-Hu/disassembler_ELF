#include "../include/utility.h"
#include <stdio.h>
#include <time.h>

using namespace std;


std::wstring StringToWString(const std::string &str)
{
	std::wstring wstr(str.length(), L' ');
	std::copy(str.begin(), str.end(), wstr.begin());
	return wstr;
}

std::string WStringToString(const std::wstring &wstr)
{
	std::string str(wstr.length(), ' ');
	std::copy(wstr.begin(), wstr.end(), str.begin());
	return str;
}

int hs2i(const char *pbSrc, const int nLen)
{
	int ret = 0;
	char h;
	char s;
	int i;

	for (i = 0; i<nLen; i++)
	{
		h = pbSrc[i];

		s = toupper(h) - 0x30;
		if (s > 9)
			s -= 7;

		ret = s + ret * 16;
	}
	return ret;
}

int hs2i(std::string src)
{
	return hs2i(src.c_str(), src.size());
}


