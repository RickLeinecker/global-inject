#include "stdafx.h"
#include "functions.h"
#include "engine_control.h"
#include <aclapi.h>

//https://m417z.com/Implementing-Global-Injection-and-Hooking-in-Windows/
//https://github.com/m417z/global-inject-demo

#define BUF_SIZE (2048*10)
TCHAR szName[] = TEXT("Global\\HookingDemo");
HANDLE hMapFile = NULL;
LPCTSTR pBuf = NULL;

void createSharedMemoryFile()
{
	hMapFile = CreateFileMapping(
		INVALID_HANDLE_VALUE,    // use paging file
		NULL,                    // default security
		PAGE_READWRITE,          // read/write access
		0,                       // maximum object size (high-order DWORD)
		BUF_SIZE,                // maximum object size (low-order DWORD)
		szName);                 // name of mapping object

	if (hMapFile == NULL)
	{
		return;
	}

	SetSecurityInfo(hMapFile, SE_KERNEL_OBJECT,
		DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
		NULL, NULL, NULL, NULL);

	pBuf = (LPTSTR)MapViewOfFile(hMapFile,   // handle to map object
		FILE_MAP_ALL_ACCESS, // read/write permission
		0,
		0,
		BUF_SIZE);
}

void closeSharedMemoryFile()
{
	if (pBuf != NULL)
	{
		UnmapViewOfFile(pBuf);
	}
	if (hMapFile != NULL)
	{
		CloseHandle(hMapFile);
	}
}

int main()
{
	printf("Setting debug privilege... ");
	if (SetDebugPrivilege(TRUE)) 
	{
		printf("Done\n");
	}
	else 
	{
		printf("Failed, probably not running as admin\n");
	}

	createSharedMemoryFile();

	try 
	{
		printf("Loading engine... ");
		auto engineControl = EngineControl();
		printf("Done\n");

		while (true) 
		{
			Sleep(1000);
			int count = engineControl.HandleNewProcesses();
			if (count == 1) 
			{
				printf("Injected into a new process\n");
			}
			else if (count > 1) 
			{
				printf("Injected into %d new processes\n", count);
			}
			if (pBuf[0] != 0)
			{
				printf("%ls",pBuf);
				wcscpy((wchar_t *)pBuf, L"");
			}
		}
	}
	catch (const std::exception& e) 
	{
		printf("%s\n", e.what());
	}

	closeSharedMemoryFile();

	return 0;
}
