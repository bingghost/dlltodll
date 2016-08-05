// DLL2DLL.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <shlwapi.h>

#define SAFE_CLOSE(hf) if(hf != NULL){CloseHandle(hf);hFile = NULL;}
#define SAFE_CLOSE_FILE(f) if(f != NULL){fclose(f);f = NULL;}
#pragma comment(lib,"shlwapi.lib")

FILE* g_fDllFuncAsm = NULL;
FILE* g_fDllMainAsm = NULL;
FILE* g_fDllInc     = NULL;
FILE* g_fDllDef     = NULL;

//INC初始化数据
char g_szIncInit[] = ".386\r\n"
                     ".model flat,stdcall\r\n"
                     "option casemap:none\r\n\r\n"
                     "include windows.inc\r\n"
                     "include kernel32.inc\r\n"
                     "includelib kernel32.lib\r\n\r\n"
                     ".data\r\n"
                     "g_hInstance    dd ?\r\n"
                     "g_dwRetAddress dd ?\r\n"
                     "g_hMyDll       dd ?\r\n";
//MainASM初始化数据
char g_szMainAsmInit[] = ".code\r\n";

char g_szMainDLLEntry[] = "DLLEntry proc _hInstance:DWORD,_dwReson:DWORD,_dwReserved:DWORD\r\n\r\n"
                          "  push _hInstance\r\n"
                          "  pop  g_hInstance\r\n\r\n"
                          "  invoke LoadLibrary,offset g_szOldDllName\r\n"
                          "  .if !eax\r\n"
                          "     int 3\r\n"
                          "  .endif\r\n"
                          "  mov g_hMyDll,eax\r\n";

char g_szMainEntryEnd[] = "\r\n  mov eax,TRUE\r\n"
                          "  ret\r\n\r\n"
                          "DLLEntry endp\r\n\r\n"
                          "end DLLEntry\r\n";

//Def初始化数据
char g_szDefInit[] = "EXPORTS\r\n";

char g_szFuncFormat[] = "%s proc\r\n\r\n"
                        "  pop  g_dwRetAddress\r\n"
                        "  call %s\r\n"
                        "  push g_dwRetAddress\r\n"
                        "  ret\r\n\r\n"
                        "%s endp\r\n\r\n";

char g_szMainFuncFormatName[] = "  invoke GetProcAddress,g_hMyDll,L(\"%s\")\r\n"
                                "  .if !eax\r\n"
                                "    int 3\r\n"
                                "  .endif\r\n"
                                "  mov  %s,eax\r\n\r\n";

char g_szMainFuncFormatNum[] = "  invoke GetProcAddress,g_hMyDll,%d\r\n"
                               "  .if !eax\r\n"
                               "    int 3\r\n"
                               "  .endif\r\n"
                               "  mov  %s,eax\r\n\r\n";

char g_szBuffer[512] = {0};   //全局缓冲区

DWORD g_nIndex = 0;           //全局序号函数索引

/*******************************************************************************
 *功  能:RVA To FOA
 *参  数:
 *   void *lpFileHead:指向DOS头指针
 *   DWORD dwRVA:需要转换的RVA
 *返回值:
 *   返回转换后的FOA,转换失败返回0
 ******************************************************************************/
DWORD RVAToOffset(void *lpFileHead,DWORD dwRVA)
{
  PIMAGE_DOS_HEADER lpDosHeader = NULL;
  PIMAGE_NT_HEADERS lpNtHeader = NULL;
  PIMAGE_SECTION_HEADER lpSection = NULL;
  DWORD  dwRet = 0;
  
  lpDosHeader = (PIMAGE_DOS_HEADER)lpFileHead;
  lpNtHeader  = (PIMAGE_NT_HEADERS)((char *)lpFileHead + lpDosHeader->e_lfanew);
  lpSection   = (PIMAGE_SECTION_HEADER)((char *)lpNtHeader + (sizeof IMAGE_NT_HEADERS));
  
  DWORD nNumOfSection = lpNtHeader->FileHeader.NumberOfSections;
  
  for (DWORD i = 0;i < nNumOfSection;i++)
  {
    DWORD n = lpSection->SizeOfRawData + lpSection->VirtualAddress;
    
    if ((dwRVA >= lpSection->VirtualAddress) && (dwRVA < n))
    {
      //存在于当前的节
      dwRet  = dwRVA - lpSection->VirtualAddress;
      dwRet  = dwRet + lpSection->PointerToRawData;
      
      return dwRet;
    }
    lpSection++;
  }
  
  return 0;
}

//遍历导出表 得到每一项
BOOL LoopExport(unsigned char* lpDllImage)
{
  PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpDllImage;
  PIMAGE_NT_HEADERS lpNtHeader = NULL;
  char szFunName[MAX_PATH] = {0};
  char szValueName[MAX_PATH] = {0};
  DWORD nFunNum = 0;
  g_nIndex = 0;

  //参数检查
  if (lpDosHeader == NULL)
  {
    return TRUE;
  }
  
  lpNtHeader  = (PIMAGE_NT_HEADERS)((char *)lpDosHeader + lpDosHeader->e_lfanew);
  
  DWORD dwRVAExport = lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;  
  if (dwRVAExport == 0)
  {
    printf("该PE文件无导出表\r\n");
    return TRUE;
  }
  
  //将RVA转换成FOA
  DWORD dwFOAExport = RVAToOffset(lpDllImage,dwRVAExport);
  PIMAGE_EXPORT_DIRECTORY lpExport = (PIMAGE_EXPORT_DIRECTORY)(lpDllImage + dwFOAExport);

  DWORD  dwFOAFunc    = RVAToOffset(lpDllImage,lpExport->AddressOfFunctions);
  DWORD  dwFOAFunName = RVAToOffset(lpDllImage,lpExport->AddressOfNames);
  DWORD  dwFOAFunOrd  = RVAToOffset(lpDllImage,lpExport->AddressOfNameOrdinals);
  DWORD* lpFuncs      = (DWORD*)(lpDllImage + dwFOAFunc);
  DWORD* lpFuncName   = (DWORD*)(lpDllImage + dwFOAFunName);
  WORD*  lpFuncOrd    = (WORD*)(lpDllImage + dwFOAFunOrd);
  WORD*  lpFuncOrdBegin = lpFuncOrd;
  BOOL   isName       = FALSE;
  DWORD  nNameCount   = 0;

  //遍历导出表
  for (DWORD i = 0;i < lpExport->NumberOfFunctions;i++)
  {
    //函数序号
    nFunNum = lpExport->Base + i;

    //判断当前序号是否有值
    if (*lpFuncs == NULL)
    {
      lpFuncs++;
      continue;
    }

    //判断函数是否由于序号导出
    WORD* lpTemp = lpFuncOrdBegin;
    for (DWORD j = 0;j < lpExport->NumberOfNames;j++)
    {
      if (*lpTemp == (WORD)i)
      {
        isName = TRUE;
        goto NAME;
      }
      lpTemp++;
    }
    isName = FALSE;

NAME:
    if (!isName)
    {
      //拼凑出序号函数名称
      wsprintf(szFunName,"MyNumFun%d",g_nIndex);

      //变量名
      wsprintf(szValueName,"g_fn%s",szFunName);    //g_fn函数名

      //按序号写入def文件
      wsprintf(g_szBuffer,"%s @%d NONAME\r\n",szFunName,nFunNum);
      fwrite(g_szBuffer,strlen(g_szBuffer),1,g_fDllDef);

      //按序号写入func_asm文件
      wsprintf(g_szBuffer,g_szFuncFormat,szFunName,szValueName,szFunName);
      fwrite(g_szBuffer,strlen(g_szBuffer),1,g_fDllFuncAsm);

      //按序号写入main_asm文件
      wsprintf(g_szBuffer,g_szMainFuncFormatNum,nFunNum,szValueName);
      fwrite(g_szBuffer,strlen(g_szBuffer),1,g_fDllMainAsm);

      //按序号写入inc文件
      wsprintf(g_szBuffer,"%s dd ?\r\n",szValueName);
      fwrite(g_szBuffer,strlen(g_szBuffer),1,g_fDllInc);

      lpFuncs++;
      g_nIndex++;    // 全局序号增加
      continue;
    }

    //函数由姓名导出
    char *lpName = (char*)(lpDllImage + RVAToOffset(lpDllImage,*lpFuncName));
    
    //变量名
    wsprintf(szValueName,"g_fn%s",lpName);    //g_fn函数名
    
    //按名称写入def文件
    wsprintf(g_szBuffer,"%s @%d\r\n",lpName,nFunNum);
    fwrite(g_szBuffer,strlen(g_szBuffer),1,g_fDllDef);
    
    //按名称写入func_asm文件
    wsprintf(g_szBuffer,g_szFuncFormat,lpName,szValueName,lpName);
    fwrite(g_szBuffer,strlen(g_szBuffer),1,g_fDllFuncAsm);
    
    //按名称写入main_asm文件
    wsprintf(g_szBuffer,g_szMainFuncFormatName,lpName,szValueName);
    fwrite(g_szBuffer,strlen(g_szBuffer),1,g_fDllMainAsm);
    
    //按名称写入inc文件
    wsprintf(g_szBuffer,"%s dd ?\r\n",szValueName);
    fwrite(g_szBuffer,strlen(g_szBuffer),1,g_fDllInc);

    lpFuncs++;
    lpFuncName++;
    lpFuncOrd++;
  }

  return TRUE;
}

BOOL InitProgram(const char* lpDllPath)
{
  char szDllName[MAX_PATH] = {0};
  char szAsmFuncName[MAX_PATH] = {0};
  char szAsmMainName[MAX_PATH] = {0};
  char szIncName[MAX_PATH] = {0};
  char szDefName[MAX_PATH] = {0};

  char szBuffer[MAX_PATH + 12] = {0};

  //取文件名(包含后缀名)
  strcpy(szDllName,PathFindFileName(lpDllPath));

  //得到文件名
  int nLen = strlen(szDllName);
  szDllName[nLen - 4] = '\0';

  //拼接出需要创建的文件名
  strcpy(szAsmFuncName,szDllName);
  strcpy(szAsmMainName,szDllName);
  strcpy(szIncName,szDllName);
  strcpy(szDefName,szDllName);
  strcat(szAsmFuncName,"_1_func.asm");
  strcat(szAsmMainName,"_1_main.asm");
  strcat(szIncName,"_1.inc");
  strcat(szDefName,"_1.def");

  //创建文件
  g_fDllFuncAsm = fopen(szAsmFuncName,"wb+");
  if (g_fDllFuncAsm == NULL)
  {
    printf("ERROR:打开文件失败\r\n");
    goto EXIT_INIT;
  }

  g_fDllMainAsm = fopen(szAsmMainName,"wb+");
  if (g_fDllMainAsm == NULL)
  {
    printf("ERROR:打开文件失败\r\n");
    goto EXIT_INIT;
  }

  g_fDllInc = fopen(szIncName,"wb+");
  if (g_fDllInc == NULL)
  {
    printf("ERROR:打开文件失败\r\n");
    goto EXIT_INIT;
  }

  g_fDllDef = fopen(szDefName,"wb+");
  if (g_fDllDef == NULL)
  {
    printf("ERROR:打开文件失败\r\n");
    goto EXIT_INIT;
  }

  //向文件写入初始化数据
  wsprintf(szBuffer,"include %s\r\n\r\n",szIncName);
  fwrite(szBuffer,strlen(szBuffer),1,g_fDllMainAsm);
  fwrite(g_szIncInit,strlen(g_szIncInit),1,g_fDllInc);
  fwrite(g_szMainAsmInit,strlen(g_szMainAsmInit),1,g_fDllMainAsm);
  fwrite(g_szDefInit,strlen(g_szDefInit),1,g_fDllDef);
  wsprintf(szBuffer,"include %s\r\n\r\n",szAsmFuncName);
  fwrite(szBuffer,strlen(szBuffer),1,g_fDllMainAsm);
  fwrite(g_szMainDLLEntry,strlen(g_szMainDLLEntry),1,g_fDllMainAsm);
  wsprintf(szBuffer,"g_szOldDllName db '%s',0\r\n\r\n",lpDllPath);
  fwrite(szBuffer,strlen(szBuffer),1,g_fDllInc);
  
  //g_fn函数名称
  //
  return TRUE;
EXIT_INIT:
  SAFE_CLOSE_FILE(g_fDllFuncAsm);
  SAFE_CLOSE_FILE(g_fDllMainAsm);
  SAFE_CLOSE_FILE(g_fDllInc);
  SAFE_CLOSE_FILE(g_fDllDef);

  return FALSE;
}

BOOL EndProgram()
{
  fwrite(g_szMainEntryEnd,strlen(g_szMainEntryEnd),1,g_fDllMainAsm);

  SAFE_CLOSE_FILE(g_fDllFuncAsm);
  SAFE_CLOSE_FILE(g_fDllMainAsm);
  SAFE_CLOSE_FILE(g_fDllInc);
  SAFE_CLOSE_FILE(g_fDllDef);
  return TRUE;
}

int main(int argc, char* argv[])
{
  char szDllPath[MAX_PATH] = {0};

  //检查参数
  if (argc != 2)
  {
    printf("参数不正确\r\n");
    return 0;
  }
  
  if (!strcmp(argv[1],"-?"))
  {
    printf("帮助\r\n");
    return 0;
  }

  if (!strcmp(argv[1],"/?"))
  {
    printf("帮助\r\n");
    return 0;
  }

  //打开文件
  HANDLE hFile = CreateFile(argv[1],                          //文件路径
                            GENERIC_READ | GENERIC_WRITE,     //读写打开
                            FILE_SHARE_READ,                  //允许其他进程读此文件                 
                            NULL,                             //安全属性
                            OPEN_EXISTING,                    //打开已经存在的
                            FILE_ATTRIBUTE_NORMAL,            //普通文件
                            NULL);                            //      
  if (hFile == INVALID_HANDLE_VALUE)
  {
    printf("ERROR:打开文件失败 目标文件可能不存在\r\n");
    return 0;
  }
  
  //获取文件的大小
  DWORD nFileSize = GetFileSize(hFile,NULL);
  if (nFileSize == -1)
  {
    printf("ERROR:获取文件大小失败\r\n");
    SAFE_CLOSE(hFile);
    return 0;
  }
  
  //申请空间
  unsigned char* lpMem = new unsigned char[nFileSize];
  if (lpMem == NULL)
  {
    printf("ERROR:申请内存空间失败\r\n");
    SAFE_CLOSE(hFile);
    return 0;
  }

  //读取文件到缓冲区
  DWORD dwByteRead = 0;
  DWORD dwRet = ReadFile(hFile,lpMem,nFileSize,&dwByteRead,0);
  if (dwRet == 0)
  {
    printf("ERROR:读取文件失败\r\n");
    SAFE_CLOSE(hFile);
    return 0;
  }

  //关闭文件
  if (hFile != NULL)
  {
    CloseHandle(hFile);
    hFile = NULL;
  }

  //初始化
  InitProgram(argv[1]);
  
  //遍历导出表
  LoopExport(lpMem);

  //退出程序
  EndProgram();
  
	return 0;
}

