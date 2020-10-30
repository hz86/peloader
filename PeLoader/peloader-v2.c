#include "peloader-v2.h"

// 链表成员
typedef struct _SINGLELIST_ENTRY {
	struct _SINGLELIST_ENTRY* Next;
} SINGLELIST_ENTRY;

// 链表头
typedef struct _SINGLELIST_HEADER {
	UINT              Count;
	SINGLELIST_ENTRY* Head;
} SINGLELIST_HEADER;

// DLL数据包成员
typedef struct _DLLPACKAGE_ENTRY {
	SINGLELIST_ENTRY Entry;
	CHAR             Name[MAX_PATH];
	LPBYTE           Data;
	DWORD            DataLen;
} DLLPACKAGE_ENTRY;

// DLL数据包
typedef struct _DLLPACKAGE {
	SINGLELIST_HEADER  List;
} DLLPACKAGE;

// 自定义数据
typedef struct _PELOADER {
	SINGLELIST_HEADER  List;
	PE_IMPORT_CALLBACK ImportCallback;
	LPVOID             Param;
} PELOADER;

// 导入表句柄成员
typedef struct _MODULE_ENTRY {
	SINGLELIST_ENTRY  Entry;
	DLLPACKAGE_ENTRY* PackEntry;
	CHAR              Name[MAX_PATH];
	HMODULE           Module;
	DWORD             Count;
} MODULE_ENTRY;

// 压入成员
static int SListEntryPush(SINGLELIST_HEADER* lpHead, SINGLELIST_ENTRY* lpEntry)
{
	lpEntry->Next = lpHead->Head;
	lpHead->Head = lpEntry;
	return ++lpHead->Count;
}

// 弹出成员
static SINGLELIST_ENTRY* SListEntryPop(SINGLELIST_HEADER* lpHead)
{
	SINGLELIST_ENTRY* lpEntry = lpHead->Head;

	if (NULL != lpEntry)
	{
		lpHead->Head = lpEntry->Next;
	}

	return lpEntry;
}

// 导入表处理回调
static BOOL WINAPI PeLoader_ImportProc(
	LPVOID          lParam,
	PE_IMPORTS_TYPE dwType,
	LPCSTR          lpModuleName,
	LPCSTR          lpProcName,
	FARPROC*        lppAddress
    )
{
	PELOADER* lpPeData = (PELOADER*)lParam;

	if (NULL != lpPeData->ImportCallback)
	{
		if (TRUE == lpPeData->ImportCallback(lpPeData->Param, dwType, lpModuleName, lpProcName, lppAddress)) {
			return TRUE;
		}
	}

	if (PE_IMPORTS_TYPE_INIT == dwType)
	{
		MODULE_ENTRY* lpModuleEntry = (MODULE_ENTRY*)lpPeData->List.Head;
		while (NULL != lpModuleEntry)
		{
			if (0 == _stricmp(lpModuleEntry->Name, lpModuleName))
			{
				if (NULL == lpModuleEntry->Module) {
					lpModuleEntry->Module = PeLoader_LoadLibrary(lpModuleEntry->PackEntry->Data, 
						lpModuleEntry->PackEntry->DataLen, 0, PeLoader_ImportProc, lpPeData);
				}

				if (NULL != lpModuleEntry->Module) {
					*lppAddress = PeLoader_GetProcAddress(lpModuleEntry->Module, lpProcName);
				}

				lpModuleEntry->Count++;
				return TRUE;
			}

			lpModuleEntry = (MODULE_ENTRY*)lpModuleEntry->Entry.Next;
		}
	}
	else if (PE_IMPORTS_TYPE_FREE == dwType)
	{
		MODULE_ENTRY* lpModuleEntry = (MODULE_ENTRY*)lpPeData->List.Head;
		while (NULL != lpModuleEntry)
		{
			if (0 == _stricmp(lpModuleEntry->Name, lpModuleName))
			{
				--lpModuleEntry->Count;
				if (0 == lpModuleEntry->Count)
				{
					if (NULL != lpModuleEntry->Module) {
						PeLoader_FreeLibrary(lpModuleEntry->Module);
						lpModuleEntry->Module = NULL;
					}
				}

				return TRUE;
			}

			lpModuleEntry = (MODULE_ENTRY*)lpModuleEntry->Entry.Next;
		}
	}

	return FALSE;
}

// 创建DLL文件包
HDLLS WINAPI PeLoader_DllPackage()
{
	DLLPACKAGE* lpPack = (DLLPACKAGE*)malloc(sizeof(DLLPACKAGE));
	if (NULL != lpPack)
	{
		memset(&lpPack->List, 0, sizeof(lpPack->List));
	}

	return (HDLLS)lpPack;
}

// 添加DLL文件数据
BOOL WINAPI PeLoader_DllPackage_AddData(HDLLS hDlls, LPCSTR lpName, LPBYTE lpData, DWORD dwLen)
{
	if (strlen(lpName) >= MAX_PATH) {
		return FALSE;
	}

	DLLPACKAGE* lpPack = (DLLPACKAGE*)hDlls;
	DLLPACKAGE_ENTRY* entry = (DLLPACKAGE_ENTRY*)malloc(sizeof(DLLPACKAGE_ENTRY));
	if (NULL != entry)
	{
		entry->Data = (LPBYTE)malloc(dwLen);
		if (NULL != entry->Data)
		{
			entry->DataLen = dwLen;
			memcpy(entry->Data, lpData, dwLen);
			strcpy_s(entry->Name, MAX_PATH, lpName);
			SListEntryPush(&lpPack->List, (SINGLELIST_ENTRY*)entry);
			return TRUE;
		}

		free(entry);
	}
	
	return FALSE;
}

// 释放文件包
VOID WINAPI PeLoader_DllPackage_Free(HDLLS hDlls)
{
	DLLPACKAGE_ENTRY* entry = NULL;
	DLLPACKAGE* lpPack = (DLLPACKAGE*)hDlls;

	while (NULL != (entry = (DLLPACKAGE_ENTRY*)SListEntryPop(&lpPack->List)))
	{
		free(entry->Data);
		free(entry);
	}

	free(hDlls);
}

// 加载模块
HMODULE WINAPI PeLoader_LoadLibraryV2(HDLLS hDlls, DWORD dwFlags, PE_IMPORT_CALLBACK fnImportCallback, LPVOID lParam)
{
	DLLPACKAGE* lpPack = (DLLPACKAGE*)hDlls;
	if (NULL == lpPack)
	{
		return NULL;
	}

	PELOADER* lpPeData = (PELOADER*)malloc(sizeof(PELOADER));
	if (NULL == lpPeData)
	{
		return NULL;
	}
	
	lpPeData->Param = lParam;
	lpPeData->ImportCallback = fnImportCallback;
	memset(&lpPeData->List, 0, sizeof(lpPeData->List));

	HMODULE* lpMainModule = NULL;
	DWORD dwMainDllLen = 0;LPBYTE lpMainDllData = NULL;

	MODULE_ENTRY* lpModuleEntry = NULL;
	DLLPACKAGE_ENTRY* lpPackEntry = (DLLPACKAGE_ENTRY*)lpPack->List.Head;
	while (NULL != lpPackEntry)
	{
		lpModuleEntry = (MODULE_ENTRY*)malloc(sizeof(MODULE_ENTRY));
		if (NULL == lpModuleEntry)
		{
			goto ERRORFREE;
		}

		lpModuleEntry->Count = 0;
		lpModuleEntry->Module = NULL;
		lpModuleEntry->PackEntry = lpPackEntry;
		strcpy_s(lpModuleEntry->Name, MAX_PATH, lpPackEntry->Name);
		SListEntryPush(&lpPeData->List, (SINGLELIST_ENTRY*)lpModuleEntry);

		lpMainDllData = lpPackEntry->Data;
		dwMainDllLen = lpPackEntry->DataLen;
		lpMainModule = &lpModuleEntry->Module;

		lpPackEntry = (DLLPACKAGE_ENTRY*)lpPackEntry->Entry.Next;
	}
	
	if (NULL == lpMainDllData)
	{
		goto ERRORFREE;
	}

	HMODULE hModule = PeLoader_LoadLibrary(lpMainDllData, dwMainDllLen, dwFlags, PeLoader_ImportProc, lpPeData);
	if (NULL == hModule)
	{
		goto ERRORFREE;
	}

	*lpMainModule = hModule;
	return hModule;

ERRORFREE:

	while (NULL != (lpModuleEntry = (MODULE_ENTRY*)SListEntryPop(&lpPeData->List))) {
		free(lpModuleEntry);
	}

	free(lpPeData);
	return NULL;
}

// 释放模块
BOOL WINAPI PeLoader_FreeLibraryV2(HMODULE hMemModule)
{
	if (FALSE != PeLoader_IsModule(hMemModule))
	{
		PELOADER* lpPeData = (PELOADER*)PeLoader_GetParam(hMemModule);
		if (FALSE != PeLoader_FreeLibrary(hMemModule))
		{
			MODULE_ENTRY* lpModuleEntry = NULL;
			while (NULL != (lpModuleEntry = (MODULE_ENTRY*)SListEntryPop(&lpPeData->List))) {
				free(lpModuleEntry);
			}

			free(lpPeData);
			return TRUE;
		}
	}

	return FALSE;
}

// 获取自定义参数
LPVOID WINAPI PeLoader_GetParamV2(HMODULE hMemModule)
{
	PELOADER* lpPeData = (PELOADER*)PeLoader_GetParam(hMemModule);
	return lpPeData->Param;
}

// 获取模块名
BOOL WINAPI PeLoader_GetModuleFileNameV2(HMODULE hMemModule, LPSTR lpFilename, DWORD nSize)
{
	PELOADER* lpPeData = (PELOADER*)PeLoader_GetParam(hMemModule);
	MODULE_ENTRY* lpModuleEntry = (MODULE_ENTRY*)lpPeData->List.Head;
	while (NULL != lpModuleEntry)
	{
		if (lpModuleEntry->Module == hMemModule)
		{
			if (nSize > strlen(lpModuleEntry->Name)) {
				strcpy_s(lpFilename, nSize, lpModuleEntry->Name);
				return TRUE;
			}

			break;
		}

		lpModuleEntry = (MODULE_ENTRY*)lpModuleEntry->Entry.Next;
	}

	return FALSE;
}
