#ifndef __UTILITY_H__
#define __UTILITY_H__

#include <string>
#include <map>
#include <stdint.h>
#include <vector>
#include <stdio.h>


std::wstring StringToWString(const std::string &str);

std::string WStringToString(const std::wstring &wstr);

int hs2i(const char *pbSrc, const int nLen);

int hs2i(std::string src);

inline std::string i2s(int i)
{
	char c[16];
	sprintf(c, "%d", i);
	return std::string(c);
}

inline int s2i(std::string str)
{
	int i;
	sscanf(str.c_str(), "%D", &i);
	if (str == i2s(i))
		return i;
	else
		return -1;
}

inline std::string i2hs(int i)
{
	char c[16];
	sprintf(c, "%x", i);
	return std::string(c);
}


#endif