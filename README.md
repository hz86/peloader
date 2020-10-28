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

## 常见问题
如果DLL有系统DLL之外的依赖，则需要把依赖DLL放到exe文件目录内，或者使用导入表回调进行内存加载依赖。  
如果PeLoader_LoadLibrary失败，可从导入表回调打印输出，看看最后一个是什么，问题基本就是最后一条命令处。  
例如GetModuleFileName命令，因为实例句柄对系统不存在，所以获取不到DLL的文件路径。 需要HOOK处理。  
如果DLL加了壳，可能会加载失败。  