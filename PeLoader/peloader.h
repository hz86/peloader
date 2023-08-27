#ifndef PELOADER_H
#define PELOADER_H

#include <Windows.h>

//加载方式
#define DONT_RESOLVE_DLL_REFERENCES	0x00000001	//不初始化模块
#define LOAD_LIBRARY_AS_DATAFILE	0x00000002	//不执行入口点
#define USE_DLL_MODULE				0x00000004	//使用DLL实例句柄, 可以使用DLL内的资源,但可能导致部分api报错，比如 GetModuleFileName 有关的命令，毕竟内存句柄不是真正有效的句柄
												//不启动此选项，可能需要把dll的资源导入到exe内才能正常运行

// 导入表回调类型
typedef enum PE_IMPORTS_TYPE {
	PE_IMPORTS_TYPE_INIT,
	PE_IMPORTS_TYPE_FREE
} PE_IMPORTS_TYPE;

// 导入表回调
// 已处理返回 TRUE
typedef BOOL(WINAPI* PE_IMPORT_CALLBACK)(
	LPVOID   lParam,		// 回调参数
	PE_IMPORTS_TYPE dwType, // 操作类型
	LPCSTR   lpModuleName,	// 模块名
	LPCSTR   lpProcName,	// 函数名（值 <= 65535 则为序号）
	FARPROC* lppAddress		// 返回地址（释放时忽略）
);

#ifdef __cplusplus
extern "C" {
#endif

	// 加载模块
	HMODULE WINAPI PeLoader_LoadLibrary(LPBYTE lpData, DWORD dwLen, DWORD dwFlags, PE_IMPORT_CALLBACK fnImportCallback, LPVOID lParam);

	// 释放模块
	BOOL WINAPI PeLoader_FreeLibrary(HMODULE hMemModule);

	// 取函数地址
	FARPROC WINAPI PeLoader_GetProcAddress(HMODULE hMemModule, LPCSTR lpProcName);

	// 取入口点
	FARPROC WINAPI PeLoader_GetEntryPoint(HMODULE hMemModule);

	// 获取自定义参数
	LPVOID WINAPI PeLoader_GetParam(HMODULE hMemModule);

	// 判断句柄是否有效
	BOOL WINAPI PeLoader_IsModule(HMODULE hMemModule);

#ifdef __cplusplus
}
#endif

#endif