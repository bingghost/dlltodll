> win32asm版本dll劫持工具


# dll to dll
	1.通过遍历dll导出表.拿到所有导出函数
	2.然后自动生成asm,def,inc文件用于编译新dll
	3.asm中会自动帮助其调用原来的dll函数


>* 用于自动生成dll劫持代码
