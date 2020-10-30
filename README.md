# peloader
内存加载DLL 支持X86和X64（Memory PELoader Support X86 and X64）

## 编译
复制 peloader.h 和 peloader.c 到项目中即可。  
使用例子可看 main.c 

## 基本用法
```
DWORD len = 0;      // DLL文件大小
BYTE dll[] = { 0 }; // DLL文件数据

// 载入内存中的DLL
HMODULE hModule = PeLoader_LoadLibrary(dll, len, 0, NULL, NULL);

// 获取入口函数地址
FARPROC dllmain = PeLoader_GetEntryPoint(hModule);

// 获取函数地址
FARPROC fun = PeLoader_GetProcAddress(hModule, "FunctionName");

// 释放DLL
PeLoader_FreeLibrary(hModule);

```

## V2版本命令
```
// 把有关依赖DLL全部打包进去
HDLLS hDlls = PeLoader_DllPackage();
PeLoader_DllPackage_AddData(hDlls, "TestDllB.dll", TestDllB, TestDllBLen);
PeLoader_DllPackage_AddData(hDlls, "TestDllA.dll", TestDllA, TestDllALen);

// 加载包内的DLL，第一个DLL为主DLL
HMODULE hModule = PeLoader_LoadLibraryV2(hDlls, 0, NULL, NULL);

// 可以获取文件名
CHAR FileName[MAX_PATH];
PeLoader_GetModuleFileNameV2(hModule, FileName, MAX_PATH);

// 释放
PeLoader_FreeLibraryV2(hModule);
```

## HOOK
```

// 导入表HOOK对动态加载的DLL无效！
// 建议使用 https://github.com/microsoft/Detours 库来HOOK。

static DWORD (WINAPI *TrueGetModuleFileNameA)(HMODULE hModule, LPSTR lpFilename, DWORD nSize) = GetModuleFileNameA;
DWORD WINAPI HookGetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
{
	// 这里可以判断句柄是否内存模块
	if (PeLoader_IsModule(hModule))
	{
		// 特殊处理，因为内存模块没有文件路径，改获取exe路径
		return TrueGetModuleFileNameA(0, lpFilename, nSize);
	}

	// 原始API
	return TrueGetModuleFileNameA(hModule, lpFilename, nSize);
}

//HOOK代码
DetourTransactionBegin();
DetourUpdateThread(GetCurrentThread());
DetourAttach(&(PVOID&)TrueGetModuleFileNameA, HookGetModuleFileNameA);
DetourTransactionCommit();

```

## 常见问题
1. 如果DLL有系统DLL之外的依赖，则需要把依赖DLL放到exe文件目录内，或者使用导入表回调进行内存加载依赖。  
2. 如果PeLoader_LoadLibrary失败，可从导入表回调打印输出，看看最后一个是什么，问题基本就是最后一条命令处。  
3. 例如GetModuleFileName命令，因为实例句柄对系统不存在，所以获取不到DLL的文件路径。 需要HOOK处理。  
4. 如果DLL加了壳，可能会加载失败。 

## 捐款
![支付宝](https://github.com/hz86/peloader/blob/master/donate.jpg) 