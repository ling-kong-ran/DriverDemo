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




// �����豸�ɷ�
NTSTATUS CreateDispatch(PDEVICE_OBJECT deviceObject, PIRP irp) {
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("Open Connect");


	irp->IoStatus.Status = 0;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

// �ر��豸�ɷ�
NTSTATUS CloseDispatch(PDEVICE_OBJECT deviceObject, PIRP irp) {
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("Close Connect");


	irp->IoStatus.Status = 0;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

// �����豸�ɷ�
NTSTATUS ControlDispatch(PDEVICE_OBJECT deviceObject, PIRP irp) {
	NTSTATUS status = STATUS_SUCCESS;
	PVOID pInBuffer = 0;
	PIO_STACK_LOCATION psl = 0;
	ULONG inLen = 0;
	ULONG outLen = 0;
	ULONG opCode = 0;


	DbgBreakPoint();

	// ��ȡӦ�ó����͵�����
	pInBuffer = irp->AssociatedIrp.SystemBuffer;

	// ��ȡiRP����
	psl = IoGetCurrentIrpStackLocation(irp);

	// ��ȡ���볤��
	inLen = psl->Parameters.DeviceIoControl.InputBufferLength;

	// ��ȡ���س���
	outLen = psl->Parameters.DeviceIoControl.OutputBufferLength;

	// ��ȡ������
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

// ������ں���
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
		pDriver, // ��������
		0, // �豸��չ�ڴ��С
		&deviceName, // �豸����
		FILE_DEVICE_UNKNOWN, // �豸����
		FILE_DEVICE_SECURE_OPEN, // �̶�
		FALSE, // �Ƿ��ռ
		&pDevice // ע���Ƕ���ָ��
	);
	if (!NT_SUCCESS(status)) {
		return STATUS_SUCCESS;
	}
	// ���ý�����ʽ
	pDevice->Flags = DO_BUFFERED_IO;
	// ���÷�������
	status = IoCreateSymbolicLink(&symbolName, &deviceName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(pDevice);
		return STATUS_SUCCESS;
	}
	// ������ǲ����
	pDriver->MajorFunction[IRP_MJ_CREATE] = CreateDispatch;
	pDriver->MajorFunction[IRP_MJ_CLOSE] = CloseDispatch;
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ControlDispatch;

	return STATUS_SUCCESS;
}
