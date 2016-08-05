include DLL_TEST.inc

.code

AddTest proc
  
;  xor eax,eax
;  mov eax,ebx
;  add eax,ebx
  pop eax
  push eax
  ret

AddTest endp

SubTest proc
  
  xor eax,eax
  mov eax,ebx
  sub eax,ebx
  ret

SubTest endp

MulTest proc
  
  mov eax,8
  ret

MulTest endp


DLLEntry proc _hInstance:DWORD,_dwReson:DWORD,_dwReserved:DWORD
  
  push _hInstance
  pop g_hInstance
  mov eax,TRUE
  ret

DLLEntry endp

end DLLEntry
