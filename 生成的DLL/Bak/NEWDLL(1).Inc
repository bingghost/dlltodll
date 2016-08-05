.386
.model flat,stdcall
option casemap:none

include windows.inc
include kernel32.inc
includelib kernel32.lib

;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
;功能:----定义字符串到常量段---返回首地址
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
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
