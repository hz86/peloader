#include "peloader.h"

#define MAX(a,b) (a>b?a:b)

#ifdef _WIN64
typedef ULONGLONG	QDWORD;
typedef PULONGLONG	PQDWORD;
#else
typedef DWORD	QDWORD;
typedef PDWORD	PQDWORD;
#endif

// �����Ա
typedef struct _SINGLELIST_ENTRY {
	struct _SINGLELIST_ENTRY* Next;
} SINGLELIST_ENTRY;

// ����ͷ
typedef struct _SINGLELIST_HEADER {
	UINT              Count;
	SINGLELIST_ENTRY* Head;
} SINGLELIST_HEADER;

// DLLģ�������Ա
typedef struct _IMPORTMODULE_ENTRY {
	SINGLELIST_ENTRY Entry;
	LPCSTR           ModuleName;
	HMODULE          Module;
	UINT             Count;
} IMPORTMODULE_ENTRY;

// PE�Զ�������
typedef struct _PELOADERDATA {
	SINGLELIST_HEADER  List;
	DWORD              Flags;
	PE_IMPORT_CALLBACK ImportCallback;
	LPVOID             Param;
} PELOADERDATA;

// ȫ�־������
typedef struct _GLOBALMODULE_ENTRY {
	SINGLELIST_ENTRY Entry;
	HMODULE          Module;
} GLOBALMODULE_ENTRY;

// DLL��ڵ�
typedef BOOL(APIENTRY* DLLMAIN)(
	HMODULE	hModule,
	DWORD	fdwReason,
	LPVOID	lpvReserved
	);

// ȫ�ֱ���
static unsigned int volatile GlobalMutex = 0;
static SINGLELIST_HEADER GlobalModuleList = { 0 };

// ������
static void SpinLock()
{
	while (0 != InterlockedCompareExchange(&GlobalMutex, 1, 0)) {
		// ��ת�� GlobalMutex Ϊ0
	}
}

// �������ͷ�
static void UnSpinLock()
{
	InterlockedExchange(&GlobalMutex, 0);
}

// �����ڴ�
static LPVOID MemAlloc(LPVOID lpAddress, SIZE_T dwSize)
{
	LPVOID lpMemAddress = VirtualAlloc(lpAddress, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);	//ָ����ַ
	if (NULL == lpMemAddress) lpMemAddress = VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);	//�����ַ
	return lpMemAddress;
}

// �ͷ��ڴ�
static void MemFree(LPVOID lpAddress)
{
	VirtualFree(lpAddress, 0, MEM_RELEASE);
}

// ���������С
static DWORD AlignedSize(DWORD dwOrigin, DWORD dwAlignment)
{
	return (dwOrigin + dwAlignment - 1) / dwAlignment * dwAlignment;
}

// ѹ���Ա
static int SListEntryPush(SINGLELIST_HEADER* lpHead, SINGLELIST_ENTRY* lpEntry)
{
	lpEntry->Next = lpHead->Head;
	lpHead->Head = lpEntry;
	return ++lpHead->Count;
}

// ɾ����Ա
static SINGLELIST_ENTRY* SListEntryRemove(SINGLELIST_HEADER* lpHead, SINGLELIST_ENTRY* lpEntry)
{
	SINGLELIST_ENTRY* lpPrevEntry = NULL;
	SINGLELIST_ENTRY* lpLastEntry = lpHead->Head;

	while (NULL != lpLastEntry)
	{
		if (lpLastEntry == lpEntry)
		{
			if (NULL == lpPrevEntry) {
				lpHead->Head = lpLastEntry->Next;
			}
			else {
				lpPrevEntry->Next = lpLastEntry->Next;
			}

			--lpHead->Count;
			break;
		}

		lpPrevEntry = lpLastEntry;
		lpLastEntry = lpLastEntry->Next;
	}

	return lpLastEntry;
}

// ������Ա
static SINGLELIST_ENTRY* SListEntryPop(SINGLELIST_HEADER* lpHead)
{
	SINGLELIST_ENTRY* lpEntry = lpHead->Head;

	if (NULL != lpEntry) {
		lpHead->Head = lpEntry->Next;
		--lpHead->Count;
	}

	return lpEntry;
}

// ���PEͷ
static BOOL CheckPeHeader(LPBYTE lpData, DWORD dwLen)
{
	if (NULL == lpData) {
		return FALSE;
	}

	if (dwLen < sizeof(IMAGE_DOS_HEADER)) {
		return FALSE;
	}

	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpData;
	if (IMAGE_DOS_SIGNATURE != lpDosHeader->e_magic) {	//MZ
		return FALSE;
	}

	if (dwLen < lpDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
		return FALSE;
	}

	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(lpData + lpDosHeader->e_lfanew);
	if (IMAGE_NT_SIGNATURE != lpNtHeader->Signature) {	//PE
		return FALSE;
	}

#ifdef _WIN64
	if (IMAGE_FILE_MACHINE_AMD64 != lpNtHeader->FileHeader.Machine) {	//AMD64
		return FALSE;
	}
#else
	if (IMAGE_FILE_MACHINE_I386 != lpNtHeader->FileHeader.Machine) {	//I386
		return FALSE;
	}
#endif

	if (IMAGE_FILE_EXECUTABLE_IMAGE != (lpNtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {	//��ִ��
		return FALSE;
	}

	if (lpNtHeader->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER)) {
		return FALSE;
	}

	PIMAGE_SECTION_HEADER lpSectionHeader;
	WORD wOptionalHeaderOffset = lpNtHeader->FileHeader.SizeOfOptionalHeader - sizeof(IMAGE_OPTIONAL_HEADER);
	lpSectionHeader = (PIMAGE_SECTION_HEADER)(lpData + lpDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + wOptionalHeaderOffset);
	for (WORD i = 0; i < lpNtHeader->FileHeader.NumberOfSections; i++)
	{
		if ((lpSectionHeader[i].PointerToRawData + lpSectionHeader[i].SizeOfRawData) > dwLen) {
			return FALSE;
		}
	}

	return TRUE;
}

// �ض���
static BOOL DoRelocation(ULONG_PTR lpMemModule)
{
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpMemModule;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(lpMemModule + lpDosHeader->e_lfanew);
	QDWORD dwDelta = (QDWORD)(lpMemModule - lpNtHeader->OptionalHeader.ImageBase);

	if (0 == dwDelta || 0 == lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
		return TRUE;
	}

	DWORD dwRelocationOffset = lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	PIMAGE_BASE_RELOCATION lpBaseRelocation = (PIMAGE_BASE_RELOCATION)(lpMemModule + dwRelocationOffset);
	while (0 != lpBaseRelocation->VirtualAddress)
	{
		DWORD dwRelocationSize = (lpBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		for (DWORD i = 0; i < dwRelocationSize; i++)
		{
			WORD wRelocationValue = *((PWORD)(lpMemModule + dwRelocationOffset + sizeof(IMAGE_BASE_RELOCATION) + i * sizeof(WORD)));
			WORD wRelocationType = wRelocationValue >> 12;

			if (IMAGE_REL_BASED_DIR64 == wRelocationType && sizeof(PULONGLONG) == sizeof(PQDWORD))
			{
				PQDWORD lpAddress = (PQDWORD)(lpMemModule + lpBaseRelocation->VirtualAddress + (wRelocationValue & 4095));
				*lpAddress += dwDelta;
			}
			else if (IMAGE_REL_BASED_HIGHLOW == wRelocationType && sizeof(PDWORD) == sizeof(PQDWORD))
			{
				PQDWORD lpAddress = (PQDWORD)(lpMemModule + lpBaseRelocation->VirtualAddress + (wRelocationValue & 4095));
				*lpAddress += dwDelta;
			}
			else if (IMAGE_REL_BASED_ABSOLUTE != wRelocationType)
			{
				return FALSE;
			}
		}

		dwRelocationOffset += lpBaseRelocation->SizeOfBlock;
		lpBaseRelocation = (PIMAGE_BASE_RELOCATION)(lpMemModule + dwRelocationOffset);
	}

	return TRUE;
}

// �ͷŵ���ģ��
static VOID FreeRavAddress(PELOADERDATA* lpPeData, ULONG_PTR lpMemModule, DWORD dwSize)
{
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpMemModule;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(lpMemModule + lpDosHeader->e_lfanew);

	if (lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
	{
		DWORD i = 0;
		PIMAGE_IMPORT_DESCRIPTOR lpImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(lpMemModule + lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (0 != lpImportDescriptor[i].Name && (0 == dwSize || i < dwSize))
		{
			DWORD j = 0;
			QDWORD realIAT = 0;

			LPCSTR lpModuleName = (LPCSTR)(lpMemModule + lpImportDescriptor[i].Name);	// ģ����
			DWORD dwFirstThunk = lpImportDescriptor[i].OriginalFirstThunk ? lpImportDescriptor[i].OriginalFirstThunk : lpImportDescriptor[i].FirstThunk;	// IAT��
			while (0 != (realIAT = ((PQDWORD)(lpMemModule + dwFirstThunk))[j]))
			{
				LPCSTR lpProcName = realIAT & IMAGE_ORDINAL_FLAG ? (LPCSTR)(realIAT & 65535) : (LPCSTR)(lpMemModule + realIAT + 2);

				if (NULL != lpPeData->ImportCallback) {
					lpPeData->ImportCallback(lpPeData->Param, PE_IMPORTS_TYPE_FREE, lpModuleName, lpProcName, NULL);
				}
				
				j++;
			}

			i++;
		}

		IMPORTMODULE_ENTRY* lpEntry = NULL;
		while (NULL != (lpEntry = (IMPORTMODULE_ENTRY*)SListEntryPop(&lpPeData->List)))
		{
			for (UINT i = 0; i < lpEntry->Count; i++) {
				FreeLibrary(lpEntry->Module);
			}

			free(lpEntry);
		}
	}
}

// ��䵼���
static BOOL FillRavAddress(PELOADERDATA* lpPeData, ULONG_PTR lpMemModule, PE_IMPORT_CALLBACK fnImportCallback, LPVOID lParam)
{
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpMemModule;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(lpMemModule + lpDosHeader->e_lfanew);

	if (0 == lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		return TRUE;
	}

	DWORD i = 0;
	PIMAGE_IMPORT_DESCRIPTOR lpImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(lpMemModule + lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	while (0 != lpImportDescriptor[i].Name)
	{
		DWORD j = 0;
		QDWORD realIAT = 0;
		HMODULE hModule = NULL;

		LPCSTR lpModuleName = (LPCSTR)(lpMemModule + lpImportDescriptor[i].Name);	// ģ����
		DWORD dwFirstThunk = lpImportDescriptor[i].OriginalFirstThunk ? lpImportDescriptor[i].OriginalFirstThunk : lpImportDescriptor[i].FirstThunk;	// IAT��
		while (0 != (realIAT = ((PQDWORD)(lpMemModule + dwFirstThunk))[j]))
		{
			// ��� �� ����
			LPCSTR lpProcName = realIAT & IMAGE_ORDINAL_FLAG ? (LPCSTR)(realIAT & 65535) : (LPCSTR)(lpMemModule + realIAT + 2);

			// ������ַ
			FARPROC lpAddress = NULL;
			BOOL bPreventDefault = FALSE;
			if (NULL != fnImportCallback)
			{
				// ͨ���ص���ȡ��ַ
				bPreventDefault = fnImportCallback(lParam, PE_IMPORTS_TYPE_INIT, lpModuleName, lpProcName, &lpAddress);
			}

			// Ĭ�Ϸ�ʽ
			if (FALSE == bPreventDefault)
			{
				lpAddress = NULL;
				if (NULL == hModule)
				{
					// ����ģ��
					hModule = LoadLibraryExA(lpModuleName, NULL, 0);
					if (NULL != hModule)
					{
						// ����
						IMPORTMODULE_ENTRY* lpEntry = (IMPORTMODULE_ENTRY*)lpPeData->List.Head;
						while (NULL != lpEntry)
						{
							// ��Ϊͬһ���ڴ棬ֱ�ӱȽ�ָ��
							if (lpEntry->ModuleName == lpModuleName) {
								break;
							}

							// ��һ��
							lpEntry = (IMPORTMODULE_ENTRY*)lpEntry->Entry.Next;
						}

						if (NULL != lpEntry) {
							lpEntry->Count++; // ������+1
						}
						else
						{
							// ��������
							lpEntry = (IMPORTMODULE_ENTRY*)malloc(sizeof(IMPORTMODULE_ENTRY));
							if (NULL != lpEntry)
							{
								lpEntry->Count = 1;
								lpEntry->Module = hModule;
								lpEntry->ModuleName = lpModuleName;
								SListEntryPush(&lpPeData->List, (SINGLELIST_ENTRY*)lpEntry);
							}
							else
							{
								// �����ͷ�
								FreeLibrary(hModule);
								hModule = NULL;
							}
						}
					}
				}

				if (NULL != hModule)
				{
					// ȡ�ú���ָ��
					lpAddress = GetProcAddress(hModule, lpProcName);
				}
			}

			// �Ƿ���Ч��ַ
			if (NULL != lpAddress)
			{
				// ��Ч �ѵ�ַд��FirstThunk
				((FARPROC*)(lpMemModule + lpImportDescriptor[i].FirstThunk))[j] = lpAddress;
			}
			else
			{
				// ����ʧ��
				FreeRavAddress(lpPeData, lpMemModule, i + 1);
				return FALSE;
			}

			j++;
		}

		i++;
	}
	
	return TRUE;
}

// ����ȫ�־����Ա
static GLOBALMODULE_ENTRY* FindGlobalModuleEntry(HMODULE hMemModule)
{
	GLOBALMODULE_ENTRY* lpResult = NULL;
	SpinLock(); // �̰߳�ȫ
	
	GLOBALMODULE_ENTRY* lpEntry = (GLOBALMODULE_ENTRY*)GlobalModuleList.Head;
	while (NULL != lpEntry)
	{
		if (lpEntry->Module == hMemModule) {
			lpResult = lpEntry;
			break;
		}

		lpEntry = (GLOBALMODULE_ENTRY*)lpEntry->Entry.Next;
	}
	
	UnSpinLock();
	return lpResult;
}

// ����ģ��
HMODULE WINAPI PeLoader_LoadLibrary(LPBYTE lpData, DWORD dwLen, DWORD dwFlags, PE_IMPORT_CALLBACK fnImportCallback, LPVOID lParam)
{
	// ���PEͷ
	if (FALSE == CheckPeHeader(lpData, dwLen)) {
		return NULL;
	}

	// PEͷ
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpData;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(lpData + lpDosHeader->e_lfanew);

	// ����ӳ���С
	WORD wOptionalHeaderOffset = lpNtHeader->FileHeader.SizeOfOptionalHeader - sizeof(IMAGE_OPTIONAL_HEADER);
	PIMAGE_SECTION_HEADER lpSectionHeader = (PIMAGE_SECTION_HEADER)(lpData + lpDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + wOptionalHeaderOffset);
	DWORD dwSizeOfImage = lpNtHeader->OptionalHeader.SizeOfImage;

	// ȡ���ֵ
	for (WORD i = 0; i < lpNtHeader->FileHeader.NumberOfSections; i++) {
		dwSizeOfImage = MAX(dwSizeOfImage, AlignedSize(lpSectionHeader[i].VirtualAddress + MAX(lpSectionHeader[i].SizeOfRawData, lpSectionHeader[i].Misc.VirtualSize), lpNtHeader->OptionalHeader.SectionAlignment));
	}

	// �����쳣
	if (0 == dwSizeOfImage) {
		return NULL;
	}

	// �����ڴ� ĩβ�����Զ�������
	ULONG_PTR lpMemModule = (ULONG_PTR)MemAlloc((LPVOID)lpNtHeader->OptionalHeader.ImageBase, dwSizeOfImage + sizeof(PELOADERDATA));
	if (NULL == (LPVOID)lpMemModule) {
		return NULL;
	}

	// ��������
	memcpy((LPVOID)lpMemModule, lpData, lpDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + wOptionalHeaderOffset + lpNtHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
	for (WORD i = 0; i < lpNtHeader->FileHeader.NumberOfSections; i++)
	{
		if (0 != lpSectionHeader[i].SizeOfRawData && 0 != lpSectionHeader[i].VirtualAddress) {
			memcpy((LPVOID)(lpMemModule + lpSectionHeader[i].VirtualAddress), lpData + lpSectionHeader[i].PointerToRawData, lpSectionHeader[i].SizeOfRawData);
		}
	}

	// �Զ�������
	PELOADERDATA* lpPeData = (PELOADERDATA*)(lpMemModule + dwSizeOfImage);
	{
		lpPeData->Param = lParam;
		lpPeData->ImportCallback = fnImportCallback;
		lpPeData->Flags = dwFlags;
		lpPeData->List.Head = NULL;
		lpPeData->List.Count = 0;
	}

	// ȫ�������Ա
	GLOBALMODULE_ENTRY* lpGlobalModuleEntry = (GLOBALMODULE_ENTRY*)malloc(sizeof(GLOBALMODULE_ENTRY));
	if (NULL != lpGlobalModuleEntry)
	{
		// ����ģ����
		lpGlobalModuleEntry->Module = (HMODULE)lpMemModule;

		// �ض����ַ
		if (FALSE != DoRelocation(lpMemModule))
		{
			// ����ʼ��ģ��
			if (dwFlags == DONT_RESOLVE_DLL_REFERENCES)
			{
				SpinLock(); // �̰߳�ȫ����ȫ�־������
				SListEntryPush(&GlobalModuleList, (SINGLELIST_ENTRY*)lpGlobalModuleEntry);
				UnSpinLock();

				return (HMODULE)lpMemModule;
			}

			// ��䵼���
			if (FALSE != FillRavAddress(lpPeData, lpMemModule, fnImportCallback, lParam))
			{
				SpinLock(); // �̰߳�ȫ����ȫ�־������
				SListEntryPush(&GlobalModuleList, (SINGLELIST_ENTRY*)lpGlobalModuleEntry);
				UnSpinLock();

				// ��ִ�����
				if (IMAGE_FILE_DLL != (lpNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) || (dwFlags == LOAD_LIBRARY_AS_DATAFILE)) {
					return (HMODULE)lpMemModule;
				}

				// �Ƿ�������
				if (0 == lpNtHeader->OptionalHeader.AddressOfEntryPoint) {
					return (HMODULE)lpMemModule;
				}

				// ִ�����
				DLLMAIN dllmain = (DLLMAIN)(lpMemModule + lpNtHeader->OptionalHeader.AddressOfEntryPoint);
				if (FALSE != dllmain((HMODULE)lpMemModule, DLL_PROCESS_ATTACH, NULL)) {
					return (HMODULE)lpMemModule;
				}

				SpinLock(); // �̰߳�ȫ�Ƴ�ȫ�־��
				SListEntryRemove(&GlobalModuleList, (SINGLELIST_ENTRY*)lpGlobalModuleEntry);
				UnSpinLock();

				// �ͷŵ���ģ��
				FreeRavAddress(lpPeData, lpMemModule, 0);
			}
		}

		free(lpGlobalModuleEntry);
	}

	MemFree((LPVOID)lpMemModule);
	return NULL;
}

// �ͷ�ģ��
BOOL WINAPI PeLoader_FreeLibrary(HMODULE hMemModule)
{
	GLOBALMODULE_ENTRY* lpGlobalModuleEntry = FindGlobalModuleEntry(hMemModule);
	if (NULL == lpGlobalModuleEntry) {
		return FALSE;
	}

	ULONG_PTR lpMemModule = (ULONG_PTR)hMemModule;
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpMemModule;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(lpMemModule + lpDosHeader->e_lfanew);

	// �����С
	WORD wOptionalHeaderOffset = lpNtHeader->FileHeader.SizeOfOptionalHeader - sizeof(IMAGE_OPTIONAL_HEADER);
	PIMAGE_SECTION_HEADER lpSectionHeader = (PIMAGE_SECTION_HEADER)(lpMemModule + lpDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + wOptionalHeaderOffset);
	DWORD dwSizeOfImage = lpNtHeader->OptionalHeader.SizeOfImage;

	// ȡ���ֵ
	for (WORD i = 0; i < lpNtHeader->FileHeader.NumberOfSections; i++) {
		dwSizeOfImage = MAX(dwSizeOfImage, AlignedSize(lpSectionHeader[i].VirtualAddress + MAX(lpSectionHeader[i].SizeOfRawData, lpSectionHeader[i].Misc.VirtualSize), lpNtHeader->OptionalHeader.SectionAlignment));
	}

	// ���ݼ��ط�ʽ����
	PELOADERDATA* lpPeData = (PELOADERDATA*)(lpMemModule + dwSizeOfImage);
	if (IMAGE_FILE_DLL == (lpNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) && (DONT_RESOLVE_DLL_REFERENCES != lpPeData->Flags) && (LOAD_LIBRARY_AS_DATAFILE != lpPeData->Flags))
	{
		if (0 != lpNtHeader->OptionalHeader.AddressOfEntryPoint) {
			DLLMAIN dllmain = (DLLMAIN)(lpMemModule + lpNtHeader->OptionalHeader.AddressOfEntryPoint);
			dllmain((HMODULE)lpMemModule, DLL_PROCESS_DETACH, NULL);
		}
	}

	SpinLock(); // �̰߳�ȫ�Ƴ�ȫ�־��
	SListEntryRemove(&GlobalModuleList, (SINGLELIST_ENTRY*)lpGlobalModuleEntry);
	UnSpinLock();

	// �ͷŵ���ģ��
	if (DONT_RESOLVE_DLL_REFERENCES != lpPeData->Flags) {
		FreeRavAddress(lpPeData, lpMemModule, 0);
	}

	free(lpGlobalModuleEntry);
	MemFree(hMemModule);
	return TRUE;
}

// ȡ������ַ
FARPROC WINAPI PeLoader_GetProcAddress(HMODULE hMemModule, LPCSTR lpProcName)
{
	ULONG_PTR lpMemModule = (ULONG_PTR)hMemModule;
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpMemModule;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(lpMemModule + lpDosHeader->e_lfanew);

	// �Ƿ���ڵ�����
	if (lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0)
	{
		// �������ַ
		PIMAGE_EXPORT_DIRECTORY lpExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(lpMemModule + lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		PDWORD lpAddressOfFunctions = (PDWORD)(lpMemModule + lpExportDirectory->AddressOfFunctions);
		DWORD dwOrdinals = (DWORD)((ULONG_PTR)lpProcName - lpExportDirectory->Base);

		// �Ƿ����
		if (dwOrdinals >= 0 && dwOrdinals <= lpExportDirectory->NumberOfFunctions)
		{
			// ֱ�Ӹ�������ȡ�ý��
			return (FARPROC)(lpMemModule + lpAddressOfFunctions[dwOrdinals]);
		}
		else
		{
			// ����ָ������
			PDWORD lpAddressOfNames = (PDWORD)(lpMemModule + lpExportDirectory->AddressOfNames);
			PWORD lpAddressOfNameOrdinals = (PWORD)(lpMemModule + lpExportDirectory->AddressOfNameOrdinals);

			for (DWORD i = 0; i < lpExportDirectory->NumberOfNames; i++)
			{
				LPSTR lpName = (LPSTR)(lpMemModule + lpAddressOfNames[i]);
				if (0 == strcmp(lpProcName, lpName))
				{
					dwOrdinals = lpAddressOfNameOrdinals[i];
					if (dwOrdinals >= 0 && dwOrdinals <= lpExportDirectory->NumberOfFunctions) {
						return (FARPROC)(lpMemModule + lpAddressOfFunctions[dwOrdinals]);
					}
				}
			}
		}
	}

	return NULL;
}

// ȡ��ڵ�
FARPROC WINAPI PeLoader_GetEntryPoint(HMODULE hMemModule)
{
	ULONG_PTR lpMemModule = (ULONG_PTR)hMemModule;
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpMemModule;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(lpMemModule + lpDosHeader->e_lfanew);
	return (FARPROC)(lpMemModule + lpNtHeader->OptionalHeader.AddressOfEntryPoint);
}

// ��ȡ�Զ������
LPVOID WINAPI PeLoader_GetParam(HMODULE hMemModule)
{
	ULONG_PTR lpMemModule = (ULONG_PTR)hMemModule;
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpMemModule;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(lpMemModule + lpDosHeader->e_lfanew);

	//�����С
	WORD wOptionalHeaderOffset = lpNtHeader->FileHeader.SizeOfOptionalHeader - sizeof(IMAGE_OPTIONAL_HEADER);
	PIMAGE_SECTION_HEADER lpSectionHeader = (PIMAGE_SECTION_HEADER)(lpMemModule + lpDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + wOptionalHeaderOffset);
	DWORD dwSizeOfImage = lpNtHeader->OptionalHeader.SizeOfImage;

	// ȡ���ֵ
	for (WORD i = 0; i < lpNtHeader->FileHeader.NumberOfSections; i++) {
		dwSizeOfImage = MAX(dwSizeOfImage, AlignedSize(lpSectionHeader[i].VirtualAddress + MAX(lpSectionHeader[i].SizeOfRawData, lpSectionHeader[i].Misc.VirtualSize), lpNtHeader->OptionalHeader.SectionAlignment));
	}

	// ȡ���Զ������
	PELOADERDATA* lpPeData = (PELOADERDATA*)(lpMemModule + dwSizeOfImage);
	return lpPeData->Param;
}

// �жϾ���Ƿ���Ч
BOOL WINAPI PeLoader_IsModule(HMODULE hMemModule)
{
	return NULL != FindGlobalModuleEntry(hMemModule);
}
