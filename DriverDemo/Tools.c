#include "Tools.h"

// 获取某个驱动对象 例如 L"\\Driver\\DriverDemo"
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


PRTL_PROCESS_MODULE_INFORMATION GetSystemModuleByName(PUCHAR moduleName, PULONG pModuleSize){
	PRTL_PROCESS_MODULE_INFORMATION result = 0;



	return result;
}

HANDLE ptHandle = 0;