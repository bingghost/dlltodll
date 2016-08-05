include 1_1.inc

.code
include 1_1_func.asm

DLLEntry proc _hInstance:DWORD,_dwReson:DWORD,_dwReserved:DWORD

  push _hInstance
  pop  g_hInstance

  invoke LoadLibrary,offset g_szOldDllName
  .if !eax
     int 3
  .endif
  mov g_hMyDll,eax
  invoke GetProcAddress,g_hMyDll,L("AddTest")
  .if !eax
    int 3
  .endif
  mov  g_fnAddTest,eax

  invoke GetProcAddress,g_hMyDll,3
  .if !eax
    int 3
  .endif
  mov  g_fnMyNumFun0,eax

  invoke GetProcAddress,g_hMyDll,L("SubTest")
  .if !eax
    int 3
  .endif
  mov  g_fnSubTest,eax

  mov eax,TRUE
  ret

DLLEntry endp

end DLLEntry
