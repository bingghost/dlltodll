.386
.model flat,stdcall
option casemap:none

include C:\RadASM\masm32\include\windows.inc
include C:\RadASM\masm32\include\kernel32.inc
includelib C:\RadASM\masm32\lib\kernel32.lib

L	macro	@var:VARARG
	LOCAL	@lbl
	.const
	@lbl		db	@var,0
	.code
	exitm	<offset @lbl>
endm

.data
g_hInstance    dd ?
g_dwRetAddress dd ?
g_hMyDll       dd ?
g_szOldDllName db '1.dll',0

g_fnAddTest dd ?
g_fnMyNumFun0 dd ?
g_fnSubTest dd ?
