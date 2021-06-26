#include "../include/pe.h"
#include <tchar.h>
#include <TlHelp32.h>
using namespace std;

//For file ======================================================================================================

bool PE::Parser(const char* fileName,PeInfo& peInfo,parseError &error)
{
    ifstream fin;
    if(!PE::open(fileName,fin))
    {
        PE::close(fin);
        error = openError;
        return false;
    }

    if(!PE::readImageDosHeader(peInfo.dosHeader,fin))
    {
        PE::close(fin);
        error = readDosError;
        return false;
    }

    if(!PE::readImageNtHeader(peInfo.ntHeader,fin))
    {
        PE::close(fin);
        error = readNtError;
        return false;
    }

    if(!PE::readVImageSectionHeader(peInfo.vSectionHeaders,peInfo.ntHeader.FileHeader.NumberOfSections,fin))
    {
        PE::close(fin);
        error = readSectionError;
        return false;
    }

    error = noError;
    return true;

}

bool PE::open(const char* fileName,ifstream &fin)
{

    fin.open(fileName,ios::binary);
    return fin.is_open();
}

void PE::close(ifstream &fin)
{
    fin.close();
}

bool PE::readImageDosHeader(IMAGE_DOS_HEADER &imageDosHeader,ifstream &fin)
{
    fin.read((char*)&imageDosHeader,sizeof(IMAGE_DOS_HEADER));
    fin.seekg(imageDosHeader.e_lfanew,ios::beg);

    //MZ
    if(imageDosHeader.e_magic == 0x5a4d)
    {
        return true;
    }
    else
    {
        return false;
    }


}

bool PE::readImageNtHeader(IMAGE_NT_HEADERS &imageNtHeader,ifstream &fin)
{
    fin.read((char*)&imageNtHeader,sizeof(IMAGE_NT_HEADERS));

    //PE..
    if(imageNtHeader.Signature == 0x00004550)
    {
        return true;
    }
    else
    {
        return false;
    }

}

bool PE::readVImageSectionHeader(vector<IMAGE_SECTION_HEADER> &vImageSectionHeaders,int len,std::ifstream &fin)
{
    for(int i=0;i<len;i++)
    {
        IMAGE_SECTION_HEADER ish;
        memset(&ish,0,sizeof(IMAGE_SECTION_HEADER));
        fin.read((char*)&ish,sizeof(IMAGE_SECTION_HEADER));
        vImageSectionHeaders.push_back(ish);
    }

    if(len == 0)
    {
        return false;
    }
    else
    {
        return true;
    }
}


//For Process======================================================================================================

bool PE::Parser(const LPTSTR hProcessName,PeInfo& peInfo,parseError &error,DWORD baseImageAddr)
{
	HANDLE hProcess;
	if(!PE::open(hProcessName,hProcess))
	{
		error = openError;
		return false;
	}

	if(!PE::readImageDosHeader(peInfo.dosHeader,hProcess,baseImageAddr))
	{
		error = readDosError;
		return false;
	}

	if(!PE::readImageNtHeader(peInfo.ntHeader,hProcess,baseImageAddr))
	{
		error = readNtError;
		return false;
	}

	if(!PE::readVImageSectionHeader(peInfo.vSectionHeaders,peInfo.ntHeader.FileHeader.NumberOfSections,hProcess,baseImageAddr))
	{
		error = readSectionError;
		return false;
	}

	error = noError;
	return true;
	

}

bool PE::Parser(const int pid, PeInfo& peInfo, parseError &error, DWORD baseImageAddr /*= 0x400000*/)
{
	HANDLE hProcess;
	if (!PE::open(pid, hProcess))
	{
		error = openError;
		return false;
	}

	if (!PE::readImageDosHeader(peInfo.dosHeader, hProcess, baseImageAddr))
	{
		error = readDosError;
		return false;
	}

	if (!PE::readImageNtHeader(peInfo.ntHeader, hProcess, baseImageAddr))
	{
		error = readNtError;
		return false;
	}

	if (!PE::readVImageSectionHeader(peInfo.vSectionHeaders, peInfo.ntHeader.FileHeader.NumberOfSections, hProcess, baseImageAddr))
	{
		error = readSectionError;
		return false;
	}

	error = noError;
	return true;
}

bool PE::open(const LPTSTR hProcessName,HANDLE &hProcess)
{
	DWORD pid = getPid(hProcessName);
	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,FALSE,pid);
	if(hProcess>0)
		return true;
	else
		return false;
}

bool PE::open(const int pid, HANDLE &hProcess)
{
	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
	if (hProcess > 0)
		return true;
	else
		return false;
}

bool PE::readImageDosHeader(IMAGE_DOS_HEADER &imageDosHeader,HANDLE hProcess,DWORD &baseImageAddr)
{
	DWORD dwNumBytesXferred;
	bool bRet = ReadProcessMemory(hProcess,(PDWORD)baseImageAddr, &imageDosHeader, sizeof(IMAGE_DOS_HEADER), &dwNumBytesXferred);
	baseImageAddr += imageDosHeader.e_lfanew;

	if(imageDosHeader.e_magic == 0x5a4d)
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool PE::readImageNtHeader(IMAGE_NT_HEADERS &imageNtHeader,HANDLE hProcess,DWORD &baseImageAddr)
{
	DWORD dwNumBytesXferred;
	
	bool bRet = ReadProcessMemory(hProcess,(PDWORD)baseImageAddr, &imageNtHeader, sizeof(IMAGE_NT_HEADERS), &dwNumBytesXferred);  
	baseImageAddr += sizeof(IMAGE_NT_HEADERS);

	//PE..
	if(imageNtHeader.Signature == 0x00004550)
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool PE::readVImageSectionHeader(std::vector<IMAGE_SECTION_HEADER> &vImageSectionHeaders,int len,HANDLE hProcess,DWORD &baseImageAddr)
{
	for(int i=0;i<len;i++)
	{
		IMAGE_SECTION_HEADER ish;
		memset(&ish,0,sizeof(IMAGE_SECTION_HEADER));

		DWORD dwNumBytesXferred;
		bool bRet = ReadProcessMemory(hProcess,(PDWORD)(baseImageAddr),
										&ish, sizeof(IMAGE_SECTION_HEADER), &dwNumBytesXferred);  

		vImageSectionHeaders.push_back(ish);

		baseImageAddr += sizeof(IMAGE_SECTION_HEADER);
	}

	if(len == 0)
	{
		return false;
	}
	else
	{
		return true;
	}
}


//assist
DWORD PE::getPid(LPTSTR name)
{
	//��ȡ����name��ID
	HANDLE hProcSnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);//��ȡ���̿��վ��
	if(hProcSnap==INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32 pe32;
	pe32.dwSize=sizeof(PROCESSENTRY32);
	BOOL flag=Process32First(hProcSnap,&pe32);//��ȡ�б�ĵ�һ������
	while(flag)
	{
		if(!_tcscmp(pe32.szExeFile,name))
		{
			CloseHandle(hProcSnap);
			return pe32.th32ProcessID;//pid
		}
		flag=Process32Next(hProcSnap,&pe32);//��ȡ��һ������
	}
	CloseHandle(hProcSnap);
	return 0;
}


