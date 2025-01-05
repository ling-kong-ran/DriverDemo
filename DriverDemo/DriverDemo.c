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

// ��ȡĳ����������
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

// ��������
VOID HideMySelf(PVOID StartContext) {
	// ���ö�ʱ
	LARGE_INTEGER time = { 0 };
	time.QuadPart = -10000 * 5000; // 5S

	KeDelayExecutionThread(KernelMode, FALSE, &time);

	PDRIVER_OBJECT pDriver = (PDRIVER_OBJECT)StartContext;

	// ������� ����InLoadOrderLinks��һ��ģ�����Լ�
	PLDR_DATA_TABLE_ENTRY pList = (PLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
	RemoveEntryList(&pList->InLoadOrderLinks);
	// Ĩ������ Type DriverSize DriverExtension DriverInit DriverSection
	pDriver->Type = 0;
	pDriver->DriverSize = 0;
	pDriver->DriverExtension = 0;
	pDriver->DriverInit = 0;
	pDriver->DriverSection = 0;
}

// �����ɷ�
NTSTATUS CreateDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;




	Irp->IoStatus.Status = 0;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

// �ر��ɷ�
NTSTATUS CloseDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	NTSTATUS status = STATUS_SUCCESS;




	Irp->IoStatus.Status = 0;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

// ������ں���
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING regPath) {
	pDriver->DriverUnload = DriverUnload;

	NTSTATUS status = 0;

	UNICODE_STRING deviceName = { 0 };
	UNICODE_STRING symbolName = { 0 };
	RtlInitUnicodeString(&deviceName, DEVICE_NAME);
	RtlInitUnicodeString(&symbolName, SYMBOL_NAME);

	PsCreateSystemThread(
		&ptHandle,			// �߳̾�� ��Ҫͨ��ZwClose���йر�
		THREAD_ALL_ACCESS,	// �߳�Ȩ��
		NULL,				// �̶߳�������
		NULL,				// ���̾����������� ��ѡ�� ���Ĭ�ϸ��ӵ�ϵͳ����
		NULL,				// �ͻ���ʶ��������� ��ѡ��
		HideMySelf,			// �߳�Ҫִ�еĺ���
		(PVOID)pDriver		// �߳�Ҫִ�еĺ����Ĳ���
	);

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
	IoCreateSymbolicLink(&symbolName, &deviceName);
	// ������ǲ����
	pDriver->MajorFunction[IRP_MJ_CREATE] = CreateDispatch;
	pDriver->MajorFunction[IRP_MJ_CLOSE] = CloseDispatch;

	return STATUS_SUCCESS;
}
