  .386
  .model flat,stdcall
  option casemap:none
  
include windows.inc
include user32.inc
include kernel32.inc
includelib kernel32.lib
includelib user32.lib

.data
g_hInstance dd ?
g_dwRetAddress dd ?