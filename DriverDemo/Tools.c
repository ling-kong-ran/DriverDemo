#include "Tools.h"

// 获取某个驱动对象 例如 L"\\Driver\\DriverDemo"
PDRIVER_OBJECT GetDriverObjectByName(__in PCWSTR name) {
	PDRIVER_OBJECT result = 0;
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
		(PVOID)result
	);
	if (!NT_SUCCESS(ntstatus)) {
		DbgPrint("not find DriverObject!");
		return NULL;
	}
	return result;
}


PVOID GetSystemModuleByName(__in PUCHAR moduleName, __out PULONG pModuleSize, __out PSYSTEM_MODULE_INFORMATION * pModulesBuffer) {
	PVOID result = NULL;
	PSYSTEM_MODULE_INFORMATION pModules = NULL;
	ULONG returnLength = 0;

	NTSTATUS status = ZwQuerySystemInformation(
		SystemModuleInformation,
		(PVOID)pModules,
		0,
		&returnLength
	);

	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		pModules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, returnLength);

		if (!pModules) {
			DbgPrint("allocate memeory error!");
			return NULL;
		}

		status = ZwQuerySystemInformation(
			SystemModuleInformation,
			(PVOID)pModules,
			returnLength,
			&returnLength
		);

		if (NT_SUCCESS(status)) {
			for (ULONG i = 0; i < pModules->Count; i++) {
				if (strstr(pModules->Module[i].ImageName, moduleName)) {
					result = &pModules->Module[i];
					*pModuleSize = returnLength;
					break;
				}
			}
		}

		*pModulesBuffer = pModules;
	}

	return result;
}
