#include "Tools.h"

// 获取某个驱动对象 例如 L"\\Driver\\DriverDemo"
PDRIVER_OBJECT GetDriverObjectByName(_In_ PCWSTR name) {
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
		return NULL;
	}
	return result;
}


PRTL_PROCESS_MODULE_INFORMATION GetSystemModuleByName(_In_ PUCHAR moduleName, _Out_ PULONG pModuleSize) {
	PRTL_PROCESS_MODULE_INFORMATION result = 0;
	PRTL_PROCESS_MODULES pModules = 0;
	ULONG returnLength = 4096;
	NTSTATUS status = 0;

	Flag:
	status = ZwQuerySystemInformation(
		SystemModuleInformation,
		(PVOID)&pModules,
		sizeof(pModules),
		&returnLength
	);
	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		goto Flag;
	}

	if (NT_SUCCESS(status)) {
		pModules = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, returnLength);

		if (!pModules) {
			return result;
		}

		for (ULONG i = 0; i < pModules->NumberOfModules; i++) {
			if (strstr(pModules->Modules[i].FullPathName, moduleName)) {
				result = &pModules->Modules[i];
				*pModuleSize = returnLength;
				break;
			}
		}
	}

	return result;
}
