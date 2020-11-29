#include "peloader.h"

#define MAX(a,b) (a>b?a:b)

#ifdef _WIN64
typedef ULONGLONG	QDWORD;
typedef PULONGLONG	PQDWORD;
#else
typedef DWORD	QDWORD;
typedef PDWORD	PQDWORD;
#endif

// 链表成员
typedef struct _SINGLELIST_ENTRY {
	struct _SINGLELIST_ENTRY* Next;
} SINGLELIST_ENTRY;

// 链表头
typedef struct _SINGLELIST_HEADER {
	UINT              Count;
	SINGLELIST_ENTRY* Head;
} SINGLELIST_HEADER;

// DLL模块链表成员
typedef struct _IMPORTMODULE_ENTRY {
	SINGLELIST_ENTRY Entry;
	LPCSTR           ModuleName;
	HMODULE          Module;
	UINT             Count;
} IMPORTMODULE_ENTRY;

// PE自定义数据
typedef struct _PELOADERDATA {
	SINGLELIST_HEADER  List;
	DWORD              Flags;
	PE_IMPORT_CALLBACK ImportCallback;
	LPVOID             Param;
} PELOADERDATA;

// 全局句柄链表
typedef struct _GLOBALMODULE_ENTRY {
	SINGLELIST_ENTRY Entry;
	HMODULE          Module;
} GLOBALMODULE_ENTRY;

// DLL入口点
typedef BOOL(APIENTRY* DLLMAIN)(
	HMODULE	hModule,
	DWORD	fdwReason,
	LPVOID	lpvReserved
	);

// 全局变量
static unsigned int volatile GlobalMutex = 0;
static SINGLELIST_HEADER GlobalModuleList = { 0 };

// 自旋锁
static void SpinLock()
{
	while (0 != InterlockedCompareExchange(&GlobalMutex, 1, 0)) {
		// 旋转到 GlobalMutex 为0
	}
}

// 自旋锁释放
static void UnSpinLock()
{
	InterlockedExchange(&GlobalMutex, 0);
}

// 分配内存
static LPVOID MemAlloc(LPVOID lpAddress, SIZE_T dwSize)
{
	LPVOID lpMemAddress = VirtualAlloc(lpAddress, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);	//指定基址
	if (NULL == lpMemAddress) lpMemAddress = VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);	//随机基址
	return lpMemAddress;
}

// 释放内存
static void MemFree(LPVOID lpAddress)
{
	VirtualFree(lpAddress, 0, MEM_RELEASE);
}

// 计算对齐后大小
static DWORD AlignedSize(DWORD dwOrigin, DWORD dwAlignment)
{
	return (dwOrigin + dwAlignment - 1) / dwAlignment * dwAlignment;
}

// 压入成员
static int SListEntryPush(SINGLELIST_HEADER* lpHead, SINGLELIST_ENTRY* lpEntry)
{
	lpEntry->Next = lpHead->Head;
	lpHead->Head = lpEntry;
	return ++lpHead->Count;
}

// 删除成员
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

// 弹出成员
static SINGLELIST_ENTRY* SListEntryPop(SINGLELIST_HEADER* lpHead)
{
	SINGLELIST_ENTRY* lpEntry = lpHead->Head;

	if (NULL != lpEntry) {
		lpHead->Head = lpEntry->Next;
		--lpHead->Count;
	}

	return lpEntry;
}

// 检查PE头
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

	if (IMAGE_FILE_EXECUTABLE_IMAGE != (lpNtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {	//可执行
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

// 重定向
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

// 释放导入模块
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

			LPCSTR lpModuleName = (LPCSTR)(lpMemModule + lpImportDescriptor[i].Name);	// 模块名
			DWORD dwFirstThunk = lpImportDescriptor[i].OriginalFirstThunk ? lpImportDescriptor[i].OriginalFirstThunk : lpImportDescriptor[i].FirstThunk;	// IAT表
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

// 填充导入表
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

		LPCSTR lpModuleName = (LPCSTR)(lpMemModule + lpImportDescriptor[i].Name);	// 模块名
		DWORD dwFirstThunk = lpImportDescriptor[i].OriginalFirstThunk ? lpImportDescriptor[i].OriginalFirstThunk : lpImportDescriptor[i].FirstThunk;	// IAT表
		while (0 != (realIAT = ((PQDWORD)(lpMemModule + dwFirstThunk))[j]))
		{
			// 序号 或 名称
			LPCSTR lpProcName = realIAT & IMAGE_ORDINAL_FLAG ? (LPCSTR)(realIAT & 65535) : (LPCSTR)(lpMemModule + realIAT + 2);

			// 函数地址
			FARPROC lpAddress = NULL;
			BOOL bPreventDefault = FALSE;
			if (NULL != fnImportCallback)
			{
				// 通过回调获取地址
				bPreventDefault = fnImportCallback(lParam, PE_IMPORTS_TYPE_INIT, lpModuleName, lpProcName, &lpAddress);
			}

			// 默认方式
			if (FALSE == bPreventDefault)
			{
				lpAddress = NULL;
				if (NULL == hModule)
				{
					// 加载模块
					hModule = LoadLibraryExA(lpModuleName, NULL, 0);
					if (NULL != hModule)
					{
						// 查找
						IMPORTMODULE_ENTRY* lpEntry = (IMPORTMODULE_ENTRY*)lpPeData->List.Head;
						while (NULL != lpEntry)
						{
							// 因为同一块内存，直接比较指针
							if (lpEntry->ModuleName == lpModuleName) {
								break;
							}

							// 下一个
							lpEntry = (IMPORTMODULE_ENTRY*)lpEntry->Entry.Next;
						}

						if (NULL != lpEntry) {
							lpEntry->Count++; // 引用数+1
						}
						else
						{
							// 加入链表
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
								// 出错释放
								FreeLibrary(hModule);
								hModule = NULL;
							}
						}
					}
				}

				if (NULL != hModule)
				{
					// 取得函数指针
					lpAddress = GetProcAddress(hModule, lpProcName);
				}
			}

			// 是否有效地址
			if (NULL != lpAddress)
			{
				// 有效 把地址写入FirstThunk
				((FARPROC*)(lpMemModule + lpImportDescriptor[i].FirstThunk))[j] = lpAddress;
			}
			else
			{
				// 加载失败
				FreeRavAddress(lpPeData, lpMemModule, i + 1);
				return FALSE;
			}

			j++;
		}

		i++;
	}
	
	return TRUE;
}

// 查找全局句柄成员
static GLOBALMODULE_ENTRY* FindGlobalModuleEntry(HMODULE hMemModule)
{
	GLOBALMODULE_ENTRY* lpResult = NULL;
	SpinLock(); // 线程安全
	
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

// 加载模块
HMODULE WINAPI PeLoader_LoadLibrary(LPBYTE lpData, DWORD dwLen, DWORD dwFlags, PE_IMPORT_CALLBACK fnImportCallback, LPVOID lParam)
{
	// 检查PE头
	if (FALSE == CheckPeHeader(lpData, dwLen)) {
		return NULL;
	}

	// PE头
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpData;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(lpData + lpDosHeader->e_lfanew);

	// 计算映像大小
	WORD wOptionalHeaderOffset = lpNtHeader->FileHeader.SizeOfOptionalHeader - sizeof(IMAGE_OPTIONAL_HEADER);
	PIMAGE_SECTION_HEADER lpSectionHeader = (PIMAGE_SECTION_HEADER)(lpData + lpDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + wOptionalHeaderOffset);
	DWORD dwSizeOfImage = lpNtHeader->OptionalHeader.SizeOfImage;

	// 取最大值
	for (WORD i = 0; i < lpNtHeader->FileHeader.NumberOfSections; i++) {
		dwSizeOfImage = MAX(dwSizeOfImage, AlignedSize(lpSectionHeader[i].VirtualAddress + MAX(lpSectionHeader[i].SizeOfRawData, lpSectionHeader[i].Misc.VirtualSize), lpNtHeader->OptionalHeader.SectionAlignment));
	}

	// 数据异常
	if (0 == dwSizeOfImage) {
		return NULL;
	}

	// 分配内存 末尾加入自定义数据
	ULONG_PTR lpMemModule = (ULONG_PTR)MemAlloc((LPVOID)lpNtHeader->OptionalHeader.ImageBase, dwSizeOfImage + sizeof(PELOADERDATA));
	if (NULL == (LPVOID)lpMemModule) {
		return NULL;
	}

	// 加载数据
	memcpy((LPVOID)lpMemModule, lpData, lpDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + wOptionalHeaderOffset + lpNtHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
	for (WORD i = 0; i < lpNtHeader->FileHeader.NumberOfSections; i++)
	{
		if (0 != lpSectionHeader[i].SizeOfRawData && 0 != lpSectionHeader[i].VirtualAddress) {
			memcpy((LPVOID)(lpMemModule + lpSectionHeader[i].VirtualAddress), lpData + lpSectionHeader[i].PointerToRawData, lpSectionHeader[i].SizeOfRawData);
		}
	}

	// 自定义数据
	PELOADERDATA* lpPeData = (PELOADERDATA*)(lpMemModule + dwSizeOfImage);
	{
		lpPeData->Param = lParam;
		lpPeData->ImportCallback = fnImportCallback;
		lpPeData->Flags = dwFlags;
		lpPeData->List.Head = NULL;
		lpPeData->List.Count = 0;
	}

	// 全局链表成员
	GLOBALMODULE_ENTRY* lpGlobalModuleEntry = (GLOBALMODULE_ENTRY*)malloc(sizeof(GLOBALMODULE_ENTRY));
	if (NULL != lpGlobalModuleEntry)
	{
		// 设置模块句柄
		lpGlobalModuleEntry->Module = (HMODULE)lpMemModule;

		// 重定向地址
		if (FALSE != DoRelocation(lpMemModule))
		{
			// 不初始化模块
			if (dwFlags == DONT_RESOLVE_DLL_REFERENCES)
			{
				SpinLock(); // 线程安全加入全局句柄链表
				SListEntryPush(&GlobalModuleList, (SINGLELIST_ENTRY*)lpGlobalModuleEntry);
				UnSpinLock();

				return (HMODULE)lpMemModule;
			}

			// 填充导入表
			if (FALSE != FillRavAddress(lpPeData, lpMemModule, fnImportCallback, lParam))
			{
				SpinLock(); // 线程安全加入全局句柄链表
				SListEntryPush(&GlobalModuleList, (SINGLELIST_ENTRY*)lpGlobalModuleEntry);
				UnSpinLock();

				// 不执行入口
				if (IMAGE_FILE_DLL != (lpNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) || (dwFlags == LOAD_LIBRARY_AS_DATAFILE)) {
					return (HMODULE)lpMemModule;
				}

				// 是否存在入口
				if (0 == lpNtHeader->OptionalHeader.AddressOfEntryPoint) {
					return (HMODULE)lpMemModule;
				}

				// 执行入口
				DLLMAIN dllmain = (DLLMAIN)(lpMemModule + lpNtHeader->OptionalHeader.AddressOfEntryPoint);
				if (FALSE != dllmain((HMODULE)lpMemModule, DLL_PROCESS_ATTACH, NULL)) {
					return (HMODULE)lpMemModule;
				}

				SpinLock(); // 线程安全移除全局句柄
				SListEntryRemove(&GlobalModuleList, (SINGLELIST_ENTRY*)lpGlobalModuleEntry);
				UnSpinLock();

				// 释放导入模块
				FreeRavAddress(lpPeData, lpMemModule, 0);
			}
		}

		free(lpGlobalModuleEntry);
	}

	MemFree((LPVOID)lpMemModule);
	return NULL;
}

// 释放模块
BOOL WINAPI PeLoader_FreeLibrary(HMODULE hMemModule)
{
	GLOBALMODULE_ENTRY* lpGlobalModuleEntry = FindGlobalModuleEntry(hMemModule);
	if (NULL == lpGlobalModuleEntry) {
		return FALSE;
	}

	ULONG_PTR lpMemModule = (ULONG_PTR)hMemModule;
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpMemModule;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(lpMemModule + lpDosHeader->e_lfanew);

	// 计算大小
	WORD wOptionalHeaderOffset = lpNtHeader->FileHeader.SizeOfOptionalHeader - sizeof(IMAGE_OPTIONAL_HEADER);
	PIMAGE_SECTION_HEADER lpSectionHeader = (PIMAGE_SECTION_HEADER)(lpMemModule + lpDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + wOptionalHeaderOffset);
	DWORD dwSizeOfImage = lpNtHeader->OptionalHeader.SizeOfImage;

	// 取最大值
	for (WORD i = 0; i < lpNtHeader->FileHeader.NumberOfSections; i++) {
		dwSizeOfImage = MAX(dwSizeOfImage, AlignedSize(lpSectionHeader[i].VirtualAddress + MAX(lpSectionHeader[i].SizeOfRawData, lpSectionHeader[i].Misc.VirtualSize), lpNtHeader->OptionalHeader.SectionAlignment));
	}

	// 根据加载方式处理
	PELOADERDATA* lpPeData = (PELOADERDATA*)(lpMemModule + dwSizeOfImage);
	if (IMAGE_FILE_DLL == (lpNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) && (DONT_RESOLVE_DLL_REFERENCES != lpPeData->Flags) && (LOAD_LIBRARY_AS_DATAFILE != lpPeData->Flags))
	{
		if (0 != lpNtHeader->OptionalHeader.AddressOfEntryPoint) {
			DLLMAIN dllmain = (DLLMAIN)(lpMemModule + lpNtHeader->OptionalHeader.AddressOfEntryPoint);
			dllmain((HMODULE)lpMemModule, DLL_PROCESS_DETACH, NULL);
		}
	}

	SpinLock(); // 线程安全移除全局句柄
	SListEntryRemove(&GlobalModuleList, (SINGLELIST_ENTRY*)lpGlobalModuleEntry);
	UnSpinLock();

	// 释放导入模块
	if (DONT_RESOLVE_DLL_REFERENCES != lpPeData->Flags) {
		FreeRavAddress(lpPeData, lpMemModule, 0);
	}

	free(lpGlobalModuleEntry);
	MemFree(hMemModule);
	return TRUE;
}

// 取函数地址
FARPROC WINAPI PeLoader_GetProcAddress(HMODULE hMemModule, LPCSTR lpProcName)
{
	ULONG_PTR lpMemModule = (ULONG_PTR)hMemModule;
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpMemModule;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(lpMemModule + lpDosHeader->e_lfanew);

	// 是否存在导出表
	if (lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0)
	{
		// 导出表地址
		PIMAGE_EXPORT_DIRECTORY lpExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(lpMemModule + lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		PDWORD lpAddressOfFunctions = (PDWORD)(lpMemModule + lpExportDirectory->AddressOfFunctions);
		DWORD dwOrdinals = (DWORD)((ULONG_PTR)lpProcName - lpExportDirectory->Base);

		// 是否序号
		if (dwOrdinals >= 0 && dwOrdinals <= lpExportDirectory->NumberOfFunctions)
		{
			// 直接根据索引取得结果
			return (FARPROC)(lpMemModule + lpAddressOfFunctions[dwOrdinals]);
		}
		else
		{
			// 查找指定函数
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

// 取入口点
FARPROC WINAPI PeLoader_GetEntryPoint(HMODULE hMemModule)
{
	ULONG_PTR lpMemModule = (ULONG_PTR)hMemModule;
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpMemModule;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(lpMemModule + lpDosHeader->e_lfanew);
	return (FARPROC)(lpMemModule + lpNtHeader->OptionalHeader.AddressOfEntryPoint);
}

// 获取自定义参数
LPVOID WINAPI PeLoader_GetParam(HMODULE hMemModule)
{
	ULONG_PTR lpMemModule = (ULONG_PTR)hMemModule;
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpMemModule;
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)(lpMemModule + lpDosHeader->e_lfanew);

	//计算大小
	WORD wOptionalHeaderOffset = lpNtHeader->FileHeader.SizeOfOptionalHeader - sizeof(IMAGE_OPTIONAL_HEADER);
	PIMAGE_SECTION_HEADER lpSectionHeader = (PIMAGE_SECTION_HEADER)(lpMemModule + lpDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + wOptionalHeaderOffset);
	DWORD dwSizeOfImage = lpNtHeader->OptionalHeader.SizeOfImage;

	// 取最大值
	for (WORD i = 0; i < lpNtHeader->FileHeader.NumberOfSections; i++) {
		dwSizeOfImage = MAX(dwSizeOfImage, AlignedSize(lpSectionHeader[i].VirtualAddress + MAX(lpSectionHeader[i].SizeOfRawData, lpSectionHeader[i].Misc.VirtualSize), lpNtHeader->OptionalHeader.SectionAlignment));
	}

	// 取出自定义参数
	PELOADERDATA* lpPeData = (PELOADERDATA*)(lpMemModule + dwSizeOfImage);
	return lpPeData->Param;
}

// 判断句柄是否有效
BOOL WINAPI PeLoader_IsModule(HMODULE hMemModule)
{
	return NULL != FindGlobalModuleEntry(hMemModule);
}
