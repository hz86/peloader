#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include "peloader-v2.h"

unsigned int TestDllALen, TestDllBLen;
unsigned char *TestDllA = NULL, *TestDllB = NULL;

typedef const char* (*TESTA)();
typedef const char* (*TESTB)();
typedef const char* (*TESTNAME)();

// 读取文件
static unsigned char* get_file(const wchar_t* file, unsigned int* len)
{
	unsigned char* ret = NULL;
	FILE* fp = _wfopen(file, L"rb");
	if (fp)
	{
		fseek(fp, 0, SEEK_END);
		unsigned int fplen = ftell(fp);

		fseek(fp, 0, SEEK_SET);
		ret = (unsigned char*)malloc(fplen);
		fread(ret, 1, fplen, fp);

		*len = fplen;
		fclose(fp);
	}

	return ret;
}

// 一般DLL
void Test1()
{
	HMODULE hModule = PeLoader_LoadLibrary(TestDllA, TestDllALen, 0, NULL, NULL);
	if (NULL != hModule)
	{
		TESTA fnTestA = (TESTA)PeLoader_GetProcAddress(hModule, "TestA");
		if (NULL != fnTestA)
		{
			printf("%s\r\n", fnTestA());
		}
		else
		{
			printf("内存DLL 函数地址获取失败\r\n");
		}

		PeLoader_FreeLibrary(hModule);
	}
	else
	{
		printf("内存加载DLL失败\r\n");
	}
}

// DLL 有依赖系统外的DLL
void Test2()
{
	HMODULE hModule = PeLoader_LoadLibrary(TestDllB, TestDllBLen, 0, NULL, NULL);
	if (NULL != hModule)
	{
		TESTB fnTestB = (TESTB)PeLoader_GetProcAddress(hModule, "TestB");
		if (NULL != fnTestB)
		{
			printf("%s\r\n", fnTestB());
		}
		else
		{
			printf("内存DLL 函数地址获取失败\r\n");
		}

		PeLoader_FreeLibrary(hModule);
	}
	else
	{
		printf("内存加载DLL失败\r\n");
	}
}

DWORD Test3_TestDllAModuleCount = 0;
HMODULE Test3_TestDllAModule = NULL;

DWORD WINAPI HookGetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
{
	if (PeLoader_IsModule(hModule))
	{
		return GetModuleFileNameA(0, lpFilename, nSize);
	}

	return GetModuleFileNameA(hModule, lpFilename, nSize);
}

DWORD WINAPI HookGetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
{
	if (PeLoader_IsModule(hModule))
	{
		return GetModuleFileNameW(0, lpFilename, nSize);
	}

	return GetModuleFileNameW(hModule, lpFilename, nSize);
}

// 导入表回调
// 已处理返回 TRUE
BOOL WINAPI Test3_Import(
	LPVOID   lParam,		// 回调参数
	PE_IMPORTS_TYPE dwType, // 操作类型
	LPCSTR   lpModuleName,	// 模块名
	LPCSTR   lpProcName,	// 函数名（值 <= 65535 则为序号）
	FARPROC* lppAddress)		// 返回地址（释放时忽略）
{
	if (dwType == PE_IMPORTS_TYPE_INIT)
	{
		// 判断出来的DLL名称
		if (0 == _stricmp(lpModuleName, "TestDllA.dll"))
		{
			Test3_TestDllAModuleCount++;
			if (NULL == Test3_TestDllAModule)
			{
				// 内存加载
				Test3_TestDllAModule = PeLoader_LoadLibrary(TestDllA, TestDllALen, 0, NULL, NULL);
			}

			*lppAddress = PeLoader_GetProcAddress(Test3_TestDllAModule, lpProcName);
			return TRUE;
		}
		else if (0 == _stricmp(lpModuleName, "kernel32.dll"))
		{
			// 这2个是常见问题
			// 因为DLL实例句柄在系统中不存在。
			// 通过句柄获取DLL模块路径肯定是不行的。
			// 解决方法是 HOOK 导入表！但是，可能不完整，如果是动态加载DLL就无效了。
			// 这个就需要在 内存加载DLL之前，就HOOK有关API，专门处理。

			// 很重要 在说一次 下面的方法可能存在漏网。要完美解决需要HOOKAPI

			if (0 == strcmp(lpProcName, "GetModuleFileNameA"))
			{
				*lppAddress = (FARPROC)HookGetModuleFileNameA;
				return TRUE;
			}
			else if (0 == strcmp(lpProcName, "GetModuleFileNameW"))
			{
				*lppAddress = (FARPROC)HookGetModuleFileNameW;
				return TRUE;
			}
		}

		return FALSE;
	}
	else if (dwType == PE_IMPORTS_TYPE_FREE)
	{
		// 如果不是频繁加载，只是一次，可以忽略释放
		if (0 == _stricmp(lpModuleName, "TestDllA.dll"))
		{
			Test3_TestDllAModuleCount--;
			if (0 == Test3_TestDllAModuleCount)
			{
				if (NULL != Test3_TestDllAModule)
				{
					// 释放内存模块
					PeLoader_FreeLibrary(Test3_TestDllAModule);
					Test3_TestDllAModule = NULL;
				}
			}

			return TRUE;
		}
	}

	return FALSE;
}

// DLL 有依赖系统外的DLL 内存加载依赖DLL
void Test3()
{
	typedef const char* (*TESTA)();
	HMODULE hModule = PeLoader_LoadLibrary(TestDllB, TestDllBLen, 0, Test3_Import, NULL);
	if (NULL != hModule)
	{
		TESTA fnTestB = (TESTA)PeLoader_GetProcAddress(hModule, "TestB");
		if (NULL != fnTestB)
		{
			printf("内存加载依赖 %s\r\n", fnTestB());
		}
		else
		{
			printf("内存DLL 函数地址获取失败\r\n");
		}

		TESTNAME fnTestName = (TESTNAME)PeLoader_GetProcAddress(hModule, "TestName");
		if (NULL != fnTestName)
		{
			printf("DLL路径 %s\r\n", fnTestName());
		}
		else
		{
			printf("内存DLL 函数地址获取失败\r\n");
		}

		PeLoader_FreeLibrary(hModule);
	}
	else
	{
		printf("内存加载DLL失败\r\n");
	}
}

// 测试V2版本 DLL文件包自动内存载入
void Test4()
{
	HDLLS hDlls = PeLoader_DllPackage();
	if (NULL != hDlls)
	{
		if (PeLoader_DllPackage_AddData(hDlls, "TestDllB.dll", TestDllB, TestDllBLen))
		{
			if (PeLoader_DllPackage_AddData(hDlls, "TestDllA.dll", TestDllA, TestDllALen))
			{
				HMODULE hModule = PeLoader_LoadLibraryV2(hDlls, 0, NULL, NULL);
				if (NULL != hModule)
				{
					CHAR FileName[MAX_PATH];
					PeLoader_GetModuleFileNameV2(hModule, FileName, MAX_PATH);

					TESTB fnTestB = (TESTB)PeLoader_GetProcAddress(hModule, "TestB");
					printf("%s , %s\r\n", fnTestB(), FileName);

					PeLoader_FreeLibraryV2(hModule);
				}
				else
				{
					printf("内存加载DLL失败\r\n");
				}
			}
			else
			{
				printf("文件包添加DLL\r\n");
			}
		}
		else
		{
			printf("文件包添加DLL\r\n");
		}

		PeLoader_DllPackage_Free(hDlls);
	}
	else
	{
		printf("文件包创建失败\r\n");
	}
}

int main()
{
	TestDllA = get_file(L"TestDllA.dll", &TestDllALen);
	TestDllB = get_file(L"TestDllB.dll", &TestDllBLen);

	if (NULL == TestDllA)
	{
		printf("DLLA 文件不存在\r\n");
		return 0;
	}

	if (NULL == TestDllB)
	{
		printf("DLLB 文件不存在\r\n");
		return 0;
	}

	while (1)
	{
		Test1();
		Test2();
		Test3();
		Test4();
	}
}
