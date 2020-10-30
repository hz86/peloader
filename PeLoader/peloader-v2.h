#ifndef PELOADER_V2_H
#define PELOADER_V2_H

#include "peloader.h"

// DLL文件包句柄
typedef LPBYTE HDLLS;

#ifdef __cplusplus
extern "C" {
#endif

	// 创建DLL文件包
	HDLLS WINAPI PeLoader_DllPackage();

	// 添加DLL文件数据 第一个DLL作为启动DLL
	BOOL WINAPI PeLoader_DllPackage_AddData(HDLLS hDlls, LPCSTR lpName, LPBYTE lpData, DWORD dwLen);

	// 释放文件包
	VOID WINAPI PeLoader_DllPackage_Free(HDLLS hDlls);

	// 加载模块
	HMODULE WINAPI PeLoader_LoadLibraryV2(HDLLS hDlls, DWORD dwFlags, PE_IMPORT_CALLBACK fnImportCallback, LPVOID lParam);

	// 释放模块
	BOOL WINAPI PeLoader_FreeLibraryV2(HMODULE hMemModule);

	// 获取自定义参数
	LPVOID WINAPI PeLoader_GetParamV2(HMODULE hMemModule);

	// 获取模块名
	BOOL WINAPI PeLoader_GetModuleFileNameV2(HMODULE hMemModule, LPSTR lpFilename, DWORD nSize);

#ifdef __cplusplus
}
#endif

#endif