#include "stdafx.h"
#include "customization_session.h"
#include "session_private_namespace.h"
#include "logger.h"
#include <mutex>

extern HINSTANCE g_hDllInst;

namespace
{
	wchar_t dataToWrite[5000];

	#define ENCRYPTION_LIST_SIZE 2

	struct RegistryKeysToEncrypt
	{
		HKEY key;
		wchar_t keyName[256];
		wchar_t valueName[256];
		HKEY openKey;
	};

	static struct RegistryKeysToEncrypt list[] =
	{
		{ HKEY_LOCAL_MACHINE, L"Software\\Key1", L"SensitiveData1", 0},
		{ HKEY_LOCAL_MACHINE, L"Software\\Key2", L"SensitiveData2", 0}
	};

	void clearOpenedKeys()
	{
		for (int i = 0; i < ENCRYPTION_LIST_SIZE; i++)
		{
			list[i].openKey = 0;
		}
	}

	int keyInList(HKEY key, LPCWSTR keyName, HKEY openKey)
	{
		int returnIndex = -1;

		for (int i = 0; i < ENCRYPTION_LIST_SIZE; i++)
		{
			if ((list[i].key == key || list[i].key == (HKEY)0xffff) && wcscmp(list[i].keyName, keyName) == 0)
			{
				list[i].openKey = openKey;
				return i;
			}
		}

		return returnIndex;
	}

	int inList(LPCWSTR valueName, HKEY openKey)
	{

		for (int i = 0; i < ENCRYPTION_LIST_SIZE; i++)
		{
			if (wcscmp(list[i].valueName, valueName) == 0 /* && list[i].openKey == openKey */)
			{
				return i;
			}
		}

		return -1;
	}

	int clearOpenKey(HKEY openKey)
	{
		for (int i = 0; i < ENCRYPTION_LIST_SIZE; i++)
		{
			if (list[i].openKey == openKey)
			{
				list[i].openKey = 0;
				return i;
			}
		}
		return -1;
	}

	void encryptDecryptData(wchar_t* data, DWORD size)
	{
		for (DWORD i = 0; i < (size&0xfffe); i+=2)
		{
			wchar_t tmp;
			tmp = data[i];
			data[i] = data[i + 1];
			data[i + 1] = tmp;
		}
	}

	#define BUF_SIZE (2048*10)
	TCHAR szName[] = TEXT("Global\\HookingDemo");
	static std::mutex mtx;

	void sendMessage(TCHAR* message)
	{
		HANDLE hMapFile;
		TCHAR *pBuf;

		mtx.lock();
		hMapFile = OpenFileMapping(
			FILE_MAP_ALL_ACCESS,   // read/write access
			FALSE,                 // do not inherit the name
			szName);               // name of mapping object

		if (hMapFile == NULL)
		{
			mtx.unlock();
			return;
		}

		pBuf = (TCHAR *)MapViewOfFile(hMapFile, // handle to map object
			FILE_MAP_ALL_ACCESS,  // read/write permission
			0,
			0,
			BUF_SIZE);

		if (pBuf == NULL)
		{
			CloseHandle(hMapFile);
			mtx.unlock();
			return;
		}

		wcscat((wchar_t *)pBuf, message);

		UnmapViewOfFile((wchar_t*)pBuf);
		CloseHandle(hMapFile);
		mtx.unlock();
	}

	typedef int (WINAPI* REALREGCLOSEKEY)(HKEY);
	REALREGCLOSEKEY pOriginalRegCloseKey;

	int RegCloseKeyHook(HKEY hKey)
	{

		if (clearOpenKey(hKey) >= 0 )
		{
			sendMessage((TCHAR*)L"RegCloseKey\n");
		}

		return pOriginalRegCloseKey(hKey);
	}

	typedef int (WINAPI* REALREGQUERYVALUEEXW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
	REALREGQUERYVALUEEXW pOriginalRegQueryValueExW;

	int WINAPI RegQueryValueExWHook(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
	{
		LSTATUS ret = pOriginalRegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);

		int len = wcslen(lpValueName);

#if 1
		if (len < 600 && wcsncmp(lpValueName, L"Sens", 4) == 0)
		{
			wcscpy(dataToWrite, (wchar_t*)lpData);
			encryptDecryptData((wchar_t*)lpData, (*lpcbData) / 2);

			WCHAR newMessage[1025];
			wsprintf(newMessage, L"RegQueryValueExW %s decrypted to %s\n", dataToWrite, lpData);
			sendMessage(newMessage);
		}
#endif
		return ret;
	}

	typedef int (WINAPI* REALREGGETVALUEW)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD);
	REALREGGETVALUEW pOriginalRegGetValueW;

	int WINAPI RegGetValueWHook(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData)
	{
		LSTATUS ret = pOriginalRegGetValueW(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
		if (keyInList((HKEY)0xffff, lpSubKey, hKey) >= 0)
		{
			encryptDecryptData((wchar_t*)pvData, *pcbData);

			WCHAR newMessage[1025];
			wsprintf(newMessage,L"RegGetValueW %s\n", pvData);
			sendMessage(newMessage);
		}
		return ret;
	}

	typedef int (WINAPI* REALREGOPENKEYEXW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
	REALREGOPENKEYEXW pOriginalRegOpenKeyExW;

	int WINAPI RegOpenKeyExWHook(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
	{
		int ret = pOriginalRegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
		if (ret == ERROR_SUCCESS)
		{
			if (keyInList(hKey, lpSubKey, *phkResult) >= 0)
			{
				WCHAR newMessage[1025];
				wsprintf(newMessage, L"RegOpenKeyExW\nSubkey found: '%s' %ld\n", lpSubKey, *phkResult);
				sendMessage((TCHAR*)newMessage);
			}
		}
		return ret;
	}

	typedef int (WINAPI* REALREGSETVALUEEXW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
	REALREGSETVALUEEXW pOriginalRegSetValueExW;

	LSTATUS WINAPI RegSetValueExWHook(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData)
	{
		wcscpy(dataToWrite, (wchar_t*)lpData);
		int dataSize = cbData;

		if (inList(lpValueName, hKey) >= 0)
		{
			encryptDecryptData(dataToWrite, cbData - 1);

			WCHAR newMessage[1025];
			wsprintf(newMessage, L"RegSetValueExW %s encrypted to %s\n", lpData, dataToWrite);
			sendMessage(newMessage);
		}
		LSTATUS ret = pOriginalRegSetValueExW(hKey, lpValueName, Reserved, dwType, (const BYTE*)dataToWrite, dataSize);
		return ret;
	}

	typedef int (WINAPI* REALREGCREATEKEYEXW)(HKEY, LPCWSTR, DWORD, LPSTR, DWORD, REGSAM, const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
	REALREGCREATEKEYEXW pOriginalRegCreateKeyExW;

	int WINAPI RegCreateKeyExWHook(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
	{
		LSTATUS ret = pOriginalRegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
		if (ret == ERROR_SUCCESS)
		{
			if (keyInList(hKey, lpSubKey, *phkResult) >= 0)
			{
				WCHAR newMessage[1025];
				wsprintf(newMessage, L"RegCreateKeyExW\nSubkey found: '%s' %ld\n", lpSubKey, *phkResult);
				sendMessage((TCHAR*)newMessage);
			}
		}
		return ret;
	}

	MH_STATUS InitCustomizationHooks()
	{
		MH_STATUS status;

		status = MH_CreateHook(RegCreateKeyExW, (void*)RegCreateKeyExWHook, (void**)&pOriginalRegCreateKeyExW);
		if (status == MH_OK)
		{
			status = MH_QueueEnableHook(RegCreateKeyExW);
		}

		status = MH_CreateHook(RegSetValueExW, (void*)RegSetValueExWHook, (void**)&pOriginalRegSetValueExW);
		if (status == MH_OK)
		{
			status = MH_QueueEnableHook(RegSetValueExW);
		}

		status = MH_CreateHook(RegOpenKeyExW, (void*)RegOpenKeyExWHook, (void**)&pOriginalRegOpenKeyExW);
		if (status == MH_OK)
		{
			status = MH_QueueEnableHook(RegOpenKeyExW);
		}

		status = MH_CreateHook(RegGetValueW, (void*)RegGetValueWHook, (void**)&pOriginalRegGetValueW);
		if (status == MH_OK)
		{
			status = MH_QueueEnableHook(RegGetValueW);
		}

		status = MH_CreateHook(RegQueryValueExW, (void*)RegQueryValueExWHook, (void**)&pOriginalRegQueryValueExW);
		if (status == MH_OK)
		{
			status = MH_QueueEnableHook(RegQueryValueExW);
		}

		status = MH_CreateHook(RegCloseKey, (void*)RegCloseKeyHook, (void**)&pOriginalRegCloseKey);
		if (status == MH_OK)
		{
			status = MH_QueueEnableHook(RegCloseKey);
		}

		return status;
	}
}

bool CustomizationSession::Start(bool runningFromAPC, HANDLE sessionManagerProcess, HANDLE sessionMutex) noexcept
{
	auto instance = new (std::nothrow) CustomizationSession();
	if (!instance) {
		LOG(L"Allocation of CustomizationSession failed");
		return false;
	}

	if (!instance->StartAllocated(runningFromAPC, sessionManagerProcess, sessionMutex)) {
		delete instance;
		return false;
	}

	// Instance will free itself.
	return true;
}

bool CustomizationSession::StartAllocated(bool runningFromAPC, HANDLE sessionManagerProcess, HANDLE sessionMutex) noexcept
{
	// Create the session semaphore. This will block the library if another instance
	// (from another session manager process) is already injected and its customization session is active.
	WCHAR szSemaphoreName[sizeof("CustomizationSessionSemaphore-pid=1234567890")];
	swprintf_s(szSemaphoreName, L"CustomizationSessionSemaphore-pid=%u", GetCurrentProcessId());

	HRESULT hr = m_sessionSemaphore.create(1, 1, szSemaphoreName);
	if (FAILED(hr)) {
		LOG(L"Semaphore creation failed with error %08X", hr);
		return false;
	}

	m_sessionSemaphoreLock = m_sessionSemaphore.acquire();

	if (WaitForSingleObject(sessionManagerProcess, 0) != WAIT_TIMEOUT) {
		VERBOSE(L"Session manager process is no longer running");
		return false;
	}

	if (!InitSession(runningFromAPC, sessionManagerProcess)) {
		return false;
	}

	if (runningFromAPC) {
		// Create a new thread for us to allow the program's main thread to run.
		try {
			// Note: Before creating the thread, the CRT/STL bumps the
			// reference count of the module, something a plain CreateThread
			// doesn't do.
			std::thread thread(&CustomizationSession::RunAndDeleteThis, this,
				sessionManagerProcess, sessionMutex);
			thread.detach();
		}
		catch (const std::exception& e) {
			LOG(L"%S", e.what());
			UninitSession();
			return false;
		}
	}
	else {
		// No need to create a new thread, a dedicated thread was created for us
		// before injection.
		RunAndDeleteThis(sessionManagerProcess, sessionMutex);
	}

	return true;
}

bool CustomizationSession::InitSession(bool runningFromAPC, HANDLE sessionManagerProcess) noexcept
{
	MH_STATUS status = MH_Initialize();
	if (status != MH_OK) {
		LOG(L"MH_Initialize failed with %d", status);
		return false;
	}

	if (runningFromAPC) {
		// No other threads should be running, skip thread freeze.
		MH_SetThreadFreezeMethod(MH_FREEZE_METHOD_NONE_UNSAFE);
	}
	else {
		MH_SetThreadFreezeMethod(MH_FREEZE_METHOD_FAST_UNDOCUMENTED);
	}

	try {
		m_newProcessInjector.emplace(sessionManagerProcess);
	}
	catch (const std::exception& e) {
		LOG(L"InitSession failed: %S", e.what());
		m_newProcessInjector.reset();
		MH_Uninitialize();
		return false;
	}

	status = InitCustomizationHooks();
	if (status != MH_OK) {
		LOG(L"InitCustomizationHooks failed with %d", status);
	}

	status = MH_ApplyQueued();
	if (status != MH_OK) {
		LOG(L"MH_ApplyQueued failed with %d", status);
	}

	if (runningFromAPC) {
		MH_SetThreadFreezeMethod(MH_FREEZE_METHOD_FAST_UNDOCUMENTED);
	}

	return true;
}

void CustomizationSession::RunAndDeleteThis(HANDLE sessionManagerProcess, HANDLE sessionMutex) noexcept
{
	m_sessionManagerProcess.reset(sessionManagerProcess);

	if (sessionMutex) {
		m_sessionMutex.reset(sessionMutex);
	}

	// Prevent the system from displaying the critical-error-handler message box.
	// A message box like this was appearing while trying to load a dll in a
	// process with the ProcessSignaturePolicy mitigation, and it looked like this:
	// https://stackoverflow.com/q/38367847
	DWORD dwOldMode;
	SetThreadErrorMode(SEM_FAILCRITICALERRORS, &dwOldMode);

	Run();

	SetThreadErrorMode(dwOldMode, nullptr);

	delete this;
}

void CustomizationSession::Run() noexcept
{
	DWORD waitResult = WaitForSingleObject(m_sessionManagerProcess.get(), INFINITE);
	if (waitResult != WAIT_OBJECT_0) {
		LOG(L"WaitForSingleObject returned %u, last error %u", waitResult, GetLastError());
	}

	VERBOSE(L"Uninitializing and freeing library");

	UninitSession();
}

void CustomizationSession::UninitSession() noexcept
{
	MH_STATUS status = MH_Uninitialize();
	if (status != MH_OK) {
		LOG(L"MH_Uninitialize failed with status %d", status);
	}

	m_newProcessInjector.reset();
}
