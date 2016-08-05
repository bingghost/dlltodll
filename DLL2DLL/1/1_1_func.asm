AddTest proc

  pop  g_dwRetAddress
  call g_fnAddTest
  push g_dwRetAddress
  ret

AddTest endp

MyNumFun0 proc

  pop  g_dwRetAddress
  call g_fnMyNumFun0
  push g_dwRetAddress
  ret

MyNumFun0 endp

SubTest proc

  pop  g_dwRetAddress
  call g_fnSubTest
  push g_dwRetAddress
  ret

SubTest endp

