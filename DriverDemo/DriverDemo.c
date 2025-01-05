#include <ntifs.h>
#include "NtDef.h"

HANDLE ptHandle = 0;

#define DEVICE_NAME L"\\Device\\DriverDemo"
#define SYMBOL_NAME L"\\??\\DriverDemoHack"

VOID DriverUnload(PDRIVER_OBJECT pDriver) {
	if (ptHandle) {
		ZwClose(ptHandle);
		ptHandle = 0;
	}
}

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

// 创建派发
NTSTATUS CreateDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;




	Irp->IoStatus.Status = 0;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

// 关闭派发
NTSTATUS CloseDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;




	Irp->IoStatus.Status = 0;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

// 驱动入口函数
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING regPath) {
	pDriver->DriverUnload = DriverUnload;

	NTSTATUS status = 0;

	UNICODE_STRING deviceName = { 0 };
	UNICODE_STRING symbolName = { 0 };
	RtlInitUnicodeString(&deviceName, DEVICE_NAME);
	RtlInitUnicodeString(&symbolName, SYMBOL_NAME);

	PsCreateSystemThread(
		&ptHandle,			// 线程句柄 需要通过ZwClose进行关闭
		THREAD_ALL_ACCESS,	// 线程权限
		NULL,				// 线程对象属性
		NULL,				// 进程句柄【输入参数 可选】 填空默认附加到系统进程
		NULL,				// 客户标识【输入参数 可选】
		HideMySelf,			// 线程要执行的函数
		(PVOID)pDriver		// 线程要执行的函数的参数
	);

	PDEVICE_OBJECT pDevice = 0;

	status = IoCreateDevice(
		pDriver, // 驱动对象
		0, // 设备扩展内存大小
		&deviceName, // 设备名称
		FILE_DEVICE_UNKNOWN, // 设备类型
		FILE_DEVICE_SECURE_OPEN, // 固定
		FALSE, // 是否独占
		&pDevice // 注意是二级指针
	);
	if (!NT_SUCCESS(status)) {
		return STATUS_SUCCESS;
	}
	// 设置交互方式
	pDevice->Flags = DO_BUFFERED_IO;
	// 设置符号链接
	IoCreateSymbolicLink(&symbolName, &deviceName);
	// 设置派遣函数
	pDriver->MajorFunction[IRP_MJ_CREATE] = CreateDispatch;
	pDriver->MajorFunction[IRP_MJ_CLOSE] = CloseDispatch;

	return STATUS_SUCCESS;
}
