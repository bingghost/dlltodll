.386
.model flat,stdcall
option casemap:none

include windows.inc
include kernel32.inc
includelib kernel32.lib

.data
g_hInstance    dd ?
g_dwRetAddress dd ?
g_hMyDll       dd ?
g_szOldDllName db '1.dll',0

g_fnAddTest dd ?
g_fnMyNumFun0 dd ?
g_fnSubTest dd ?
