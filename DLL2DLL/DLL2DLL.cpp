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

//INC��ʼ������
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
//MainASM��ʼ������
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

//Def��ʼ������
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

char g_szBuffer[512] = {0};   //ȫ�ֻ�����

DWORD g_nIndex = 0;           //ȫ����ź�������

/*******************************************************************************
 *��  ��:RVA To FOA
 *��  ��:
 *   void *lpFileHead:ָ��DOSͷָ��
 *   DWORD dwRVA:��Ҫת����RVA
 *����ֵ:
 *   ����ת�����FOA,ת��ʧ�ܷ���0
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
      //�����ڵ�ǰ�Ľ�
      dwRet  = dwRVA - lpSection->VirtualAddress;
      dwRet  = dwRet + lpSection->PointerToRawData;
      
      return dwRet;
    }
    lpSection++;
  }
  
  return 0;
}

//���������� �õ�ÿһ��
BOOL LoopExport(unsigned char* lpDllImage)
{
  PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)lpDllImage;
  PIMAGE_NT_HEADERS lpNtHeader = NULL;
  char szFunName[MAX_PATH] = {0};
  char szValueName[MAX_PATH] = {0};
  DWORD nFunNum = 0;
  g_nIndex = 0;

  //�������
  if (lpDosHeader == NULL)
  {
    return TRUE;
  }
  
  lpNtHeader  = (PIMAGE_NT_HEADERS)((char *)lpDosHeader + lpDosHeader->e_lfanew);
  
  DWORD dwRVAExport = lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;  
  if (dwRVAExport == 0)
  {
    printf("��PE�ļ��޵�����\r\n");
    return TRUE;
  }
  
  //��RVAת����FOA
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

  //����������
  for (DWORD i = 0;i < lpExport->NumberOfFunctions;i++)
  {
    //�������
    nFunNum = lpExport->Base + i;

    //�жϵ�ǰ����Ƿ���ֵ
    if (*lpFuncs == NULL)
    {
      lpFuncs++;
      continue;
    }

    //�жϺ����Ƿ�������ŵ���
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
      //ƴ�ճ���ź�������
      wsprintf(szFunName,"MyNumFun%d",g_nIndex);

      //������
      wsprintf(szValueName,"g_fn%s",szFunName);    //g_fn������

      //�����д��def�ļ�
      wsprintf(g_szBuffer,"%s @%d NONAME\r\n",szFunName,nFunNum);
      fwrite(g_szBuffer,strlen(g_szBuffer),1,g_fDllDef);

      //�����д��func_asm�ļ�
      wsprintf(g_szBuffer,g_szFuncFormat,szFunName,szValueName,szFunName);
      fwrite(g_szBuffer,strlen(g_szBuffer),1,g_fDllFuncAsm);

      //�����д��main_asm�ļ�
      wsprintf(g_szBuffer,g_szMainFuncFormatNum,nFunNum,szValueName);
      fwrite(g_szBuffer,strlen(g_szBuffer),1,g_fDllMainAsm);

      //�����д��inc�ļ�
      wsprintf(g_szBuffer,"%s dd ?\r\n",szValueName);
      fwrite(g_szBuffer,strlen(g_szBuffer),1,g_fDllInc);

      lpFuncs++;
      g_nIndex++;    // ȫ���������
      continue;
    }

    //��������������
    char *lpName = (char*)(lpDllImage + RVAToOffset(lpDllImage,*lpFuncName));
    
    //������
    wsprintf(szValueName,"g_fn%s",lpName);    //g_fn������
    
    //������д��def�ļ�
    wsprintf(g_szBuffer,"%s @%d\r\n",lpName,nFunNum);
    fwrite(g_szBuffer,strlen(g_szBuffer),1,g_fDllDef);
    
    //������д��func_asm�ļ�
    wsprintf(g_szBuffer,g_szFuncFormat,lpName,szValueName,lpName);
    fwrite(g_szBuffer,strlen(g_szBuffer),1,g_fDllFuncAsm);
    
    //������д��main_asm�ļ�
    wsprintf(g_szBuffer,g_szMainFuncFormatName,lpName,szValueName);
    fwrite(g_szBuffer,strlen(g_szBuffer),1,g_fDllMainAsm);
    
    //������д��inc�ļ�
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

  //ȡ�ļ���(������׺��)
  strcpy(szDllName,PathFindFileName(lpDllPath));

  //�õ��ļ���
  int nLen = strlen(szDllName);
  szDllName[nLen - 4] = '\0';

  //ƴ�ӳ���Ҫ�������ļ���
  strcpy(szAsmFuncName,szDllName);
  strcpy(szAsmMainName,szDllName);
  strcpy(szIncName,szDllName);
  strcpy(szDefName,szDllName);
  strcat(szAsmFuncName,"_1_func.asm");
  strcat(szAsmMainName,"_1_main.asm");
  strcat(szIncName,"_1.inc");
  strcat(szDefName,"_1.def");

  //�����ļ�
  g_fDllFuncAsm = fopen(szAsmFuncName,"wb+");
  if (g_fDllFuncAsm == NULL)
  {
    printf("ERROR:���ļ�ʧ��\r\n");
    goto EXIT_INIT;
  }

  g_fDllMainAsm = fopen(szAsmMainName,"wb+");
  if (g_fDllMainAsm == NULL)
  {
    printf("ERROR:���ļ�ʧ��\r\n");
    goto EXIT_INIT;
  }

  g_fDllInc = fopen(szIncName,"wb+");
  if (g_fDllInc == NULL)
  {
    printf("ERROR:���ļ�ʧ��\r\n");
    goto EXIT_INIT;
  }

  g_fDllDef = fopen(szDefName,"wb+");
  if (g_fDllDef == NULL)
  {
    printf("ERROR:���ļ�ʧ��\r\n");
    goto EXIT_INIT;
  }

  //���ļ�д���ʼ������
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
  
  //g_fn��������
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

  //������
  if (argc != 2)
  {
    printf("��������ȷ\r\n");
    return 0;
  }
  
  if (!strcmp(argv[1],"-?"))
  {
    printf("����\r\n");
    return 0;
  }

  if (!strcmp(argv[1],"/?"))
  {
    printf("����\r\n");
    return 0;
  }

  //���ļ�
  HANDLE hFile = CreateFile(argv[1],                          //�ļ�·��
                            GENERIC_READ | GENERIC_WRITE,     //��д��
                            FILE_SHARE_READ,                  //�����������̶����ļ�                 
                            NULL,                             //��ȫ����
                            OPEN_EXISTING,                    //���Ѿ����ڵ�
                            FILE_ATTRIBUTE_NORMAL,            //��ͨ�ļ�
                            NULL);                            //      
  if (hFile == INVALID_HANDLE_VALUE)
  {
    printf("ERROR:���ļ�ʧ�� Ŀ���ļ����ܲ�����\r\n");
    return 0;
  }
  
  //��ȡ�ļ��Ĵ�С
  DWORD nFileSize = GetFileSize(hFile,NULL);
  if (nFileSize == -1)
  {
    printf("ERROR:��ȡ�ļ���Сʧ��\r\n");
    SAFE_CLOSE(hFile);
    return 0;
  }
  
  //����ռ�
  unsigned char* lpMem = new unsigned char[nFileSize];
  if (lpMem == NULL)
  {
    printf("ERROR:�����ڴ�ռ�ʧ��\r\n");
    SAFE_CLOSE(hFile);
    return 0;
  }

  //��ȡ�ļ���������
  DWORD dwByteRead = 0;
  DWORD dwRet = ReadFile(hFile,lpMem,nFileSize,&dwByteRead,0);
  if (dwRet == 0)
  {
    printf("ERROR:��ȡ�ļ�ʧ��\r\n");
    SAFE_CLOSE(hFile);
    return 0;
  }

  //�ر��ļ�
  if (hFile != NULL)
  {
    CloseHandle(hFile);
    hFile = NULL;
  }

  //��ʼ��
  InitProgram(argv[1]);
  
  //����������
  LoopExport(lpMem);

  //�˳�����
  EndProgram();
  
	return 0;
}

