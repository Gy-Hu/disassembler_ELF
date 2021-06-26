#ifndef __PE_H__
#define __PE_H__

#include <iostream>
#include <fstream>
#include <vector>
#include <stdint.h>

typedef struct _PeInfo
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeader;
    std::vector<IMAGE_SECTION_HEADER> vSectionHeaders;
	
}PeInfo;

enum parseError{
    noError = 0,
    openError,
    readDosError,
    readNtError,
    readSectionError
};

class PE
{
//tool functions
public:
	std::vector<IMAGE_SECTION_HEADER> fliterExeSections(std::vector<IMAGE_SECTION_HEADER>);

	// by file
public:
    static bool Parser(const char* fileName,PeInfo& peInfo,parseError &error);
private:
    static bool open(const char* fileName,std::ifstream &fin);
    static void close(std::ifstream &fin);
    static bool readImageDosHeader(IMAGE_DOS_HEADER &imageDosHeader,std::ifstream &fin);
    static bool readImageNtHeader(IMAGE_NT_HEADERS &imageNtHeader,std::ifstream &fin);
    static bool readVImageSectionHeader(std::vector<IMAGE_SECTION_HEADER> &vImageSectionHeaders,int len,std::ifstream &fin);

	//by memory
public:
	static bool Parser(const LPTSTR hProcessName,PeInfo& peInfo,parseError &error,DWORD baseImageAddr = 0x400000);    //reject
	static bool Parser(const int pid, PeInfo& peInfo, parseError &error, DWORD baseImageAddr = 0x400000);
private:
	static bool open(const LPTSTR hProcessName,HANDLE &hProcess);  //reject
	static bool open(const int pid, HANDLE &hProcess);
	static bool readImageDosHeader(IMAGE_DOS_HEADER &imageDosHeader,HANDLE hProcess,DWORD &baseImageAddr);
	static bool readImageNtHeader(IMAGE_NT_HEADERS &imageNtHeader,HANDLE hProcess,DWORD &baseImageAddr);
	static bool readVImageSectionHeader(std::vector<IMAGE_SECTION_HEADER> &vImageSectionHeaders,int len,HANDLE hProcess,DWORD &baseImageAddr);
	static DWORD getPid(LPTSTR name);

};

#endif // PE_H
