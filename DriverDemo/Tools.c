#include "NtDef.h"

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

HANDLE ptHandle = 0;

VOID OnDriverInit(PDRIVER_OBJECT pDriver) {
	PsCreateSystemThread(
		&ptHandle,			// �߳̾�� ��Ҫͨ��ZwClose���йر�
		THREAD_ALL_ACCESS,	// �߳�Ȩ��
		NULL,				// �̶߳�������
		NULL,				// ���̾����������� ��ѡ�� ���Ĭ�ϸ��ӵ�ϵͳ����
		NULL,				// �ͻ���ʶ��������� ��ѡ��
		HideMySelf,			// �߳�Ҫִ�еĺ���
		(PVOID)pDriver		// �߳�Ҫִ�еĺ����Ĳ���
	);
}