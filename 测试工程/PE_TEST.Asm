;--------------------------------------------------------------------------------
;程序环境设置
;--------------------------------------------------------------------------------
.386
.model flat,stdcall
option casemap:none
;--------------------------------------------------------------------------------
;头文件与库文件导入
;--------------------------------------------------------------------------------
include windows.inc
include kernel32.inc
include user32.inc

includelib kernel32.lib
includelib user32.lib
includelib DLL_TEST.lib

AddTest proto 

.code

start proc
  push MB_OK
  push NULL
  push NULL
  push NULL
  call AddTest
  ;invoke MessageBox,NULL,NULL,NULL,MB_OK
  invoke ExitProcess,0
start endp
;--------------------------------------------------------------------------------
end start  ;函数入口地址

