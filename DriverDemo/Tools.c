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

// 获取系统模块信息
PSYSTEM_MODULE_INFORMATION_ENTRY GetSystemModuleByName(__in PUCHAR moduleName, __out PSYSTEM_MODULE_INFORMATION* pModulesBuffer) {
	PSYSTEM_MODULE_INFORMATION_ENTRY result = NULL;
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
					break;
				}
			}
		}

		*pModulesBuffer = pModules;
	}

	return result;
}


// 定位节区RVA
ULONG GetSectionRvaByName(__in PVOID pImageBase, __in PCSTR pSectionName, __out PULONG pSectionSize) {
	// 定位PE结构
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImageBase;
	PIMAGE_NT_HEADERS pNth = (PIMAGE_NT_HEADERS)((PUCHAR)pImageBase + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNth);


	// 遍历节区
	for (size_t i = 0; i < pNth->FileHeader.NumberOfSections; i++) {
		PUCHAR  pSecName = &pSec[i].Name;
		if (_strnicmp(pSectionName, pSecName, IMAGE_SIZEOF_SHORT_NAME) == 0) {
			// 找到节区
			*pSectionSize = pSec[i].Misc.VirtualSize;
			return pSec[i].VirtualAddress;
		}
	}
	return NULL;
}

// 定位特征码
PVOID SearchCode(__in PUCHAR pModuleName, __in PUCHAR pSectionName, __in PUCHAR szCode, __in ULONG szCodeSize) {
	// 1.获取指定模块的信息
	PSYSTEM_MODULE_INFORMATION pModules = NULL;
	PSYSTEM_MODULE_INFORMATION_ENTRY pModule = GetSystemModuleByName(pModuleName, &pModules);
	if (!pModule) {
		DbgPrint("not find module!");
		return NULL;
	}

	PVOID pImageBase = pModule->Base;


	ULONG sectionSize = 0;
	// 获取节区偏移
	ULONG pSectionBaseRva = GetSectionRvaByName(pImageBase, pSectionName, &sectionSize);

	// 起始地址
	PUCHAR startAddr = !pSectionBaseRva ? (PUCHAR)pImageBase : (PUCHAR)pImageBase + pSectionBaseRva;
	// 终点地址
	PUCHAR endAddr = !pSectionBaseRva ? (PUCHAR)startAddr + sectionSize + pModule->Size : (PUCHAR)startAddr + sectionSize;

	// 2.在起始地址和终点地址之间 定位特征 通配符为? 该通配符仅占一个char 例如 "A?B"

	for (size_t p = startAddr; p < endAddr; p++) {
		char c = *(char*)p;
		// 匹配上第一个字符，如果第一个字符是通配符?也认为匹配上第一个字符
		if (c == szCode[0] || szCode[0] == '?') {
			// 比较后续字符
			PUCHAR p1 = p; // 内存指针
			PUCHAR p2 = szCode; // 特征码指针
			// 记录已匹配的长度
			ULONG matchSize = 0;
			while (matchSize < szCodeSize && (p1 < endAddr) && (*p1 == *p2 || *p2 == '?')) {
				p1++;
				p2++;
				matchSize++;
			}

			if (matchSize == szCodeSize) {
				// 匹配成功
				return p;
			}
		}
	}

	return NULL;
}