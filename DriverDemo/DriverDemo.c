#include <ntifs.h>
#include "NtDef.h"
#include "Tools.h"

#define DEVICE_NAME L"\\Device\\DriverDemo"
#define SYMBOL_NAME L"\\??\\DriverDemoHack"

#define START 0x800
#define OPCODE_1 CTL_CODE(FILE_DEVICE_UNKNOWN, START + 0x0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OPCODE_2 CTL_CODE(FILE_DEVICE_UNKNOWN, START + 0x1, METHOD_BUFFERED, FILE_ANY_ACCESS)

VOID DriverUnload(PDRIVER_OBJECT pDriver) {
	if (ptHandle) {
		ZwClose(ptHandle);
		ptHandle = 0;


		UNICODE_STRING symbolName = { 0 };
		RtlInitUnicodeString(&symbolName, SYMBOL_NAME);
		IoDeleteSymbolicLink(&symbolName);
		IoDeleteDevice(pDriver->DeviceObject);
	}
}




// 创建设备派发
NTSTATUS CreateDispatch(PDEVICE_OBJECT deviceObject, PIRP irp) {
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("Open Connect");


	irp->IoStatus.Status = 0;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

// 关闭设备派发
NTSTATUS CloseDispatch(PDEVICE_OBJECT deviceObject, PIRP irp) {
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("Close Connect");


	irp->IoStatus.Status = 0;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

// 控制设备派发
NTSTATUS ControlDispatch(PDEVICE_OBJECT deviceObject, PIRP irp) {
	NTSTATUS status = STATUS_SUCCESS;
	PVOID pInBuffer = 0;
	PIO_STACK_LOCATION psl = 0;
	ULONG inLen = 0;
	ULONG outLen = 0;
	ULONG opCode = 0;


	DbgBreakPoint();

	// 获取应用程序发送的数据
	pInBuffer = irp->AssociatedIrp.SystemBuffer;

	// 获取iRP数据
	psl = IoGetCurrentIrpStackLocation(irp);

	// 获取传入长度
	inLen = psl->Parameters.DeviceIoControl.InputBufferLength;

	// 获取返回长度
	outLen = psl->Parameters.DeviceIoControl.OutputBufferLength;

	// 获取控制码
	opCode = psl->Parameters.DeviceIoControl.IoControlCode;

	switch (opCode) {
	case OPCODE_1:
		memset(pInBuffer, 0x6, outLen);
		break;
	case OPCODE_2:
		memset(pInBuffer, 0x7, outLen);
		break;
	default:
		break;
	}

	irp->IoStatus.Status = 0;
	irp->IoStatus.Information = outLen;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

// 驱动入口函数
#pragma INITCODE
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING regPath) {
	pDriver->DriverUnload = DriverUnload;

	NTSTATUS status = 0;

	UNICODE_STRING deviceName = { 0 };
	UNICODE_STRING symbolName = { 0 };
	RtlInitUnicodeString(&deviceName, DEVICE_NAME);
	RtlInitUnicodeString(&symbolName, SYMBOL_NAME);

	//OnDriverInit(pDriver);

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
	status = IoCreateSymbolicLink(&symbolName, &deviceName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(pDevice);
		return STATUS_SUCCESS;
	}
	// 设置派遣函数
	pDriver->MajorFunction[IRP_MJ_CREATE] = CreateDispatch;
	pDriver->MajorFunction[IRP_MJ_CLOSE] = CloseDispatch;
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ControlDispatch;

	return STATUS_SUCCESS;
}
