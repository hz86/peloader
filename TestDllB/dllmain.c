#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <Windows.h>

char str[1024];
char name[1024];
HMODULE g_hModule;

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_hModule = hModule;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

const char* TestB()
{
    const char* TestA();
    sprintf(str, "Dll B, %s", TestA());
    return str;
}

const char* TestName()
{
    GetModuleFileNameA(g_hModule, name, 1024);
    return name;
}
