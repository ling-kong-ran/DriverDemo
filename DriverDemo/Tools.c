#include "Tools.h"

// ��ȡĳ���������� ���� L"\\Driver\\DriverDemo"
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

// ��ȡϵͳģ����Ϣ
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


// ��λ����RVA
ULONG GetSectionRvaByName(__in PVOID pImageBase, __in PCSTR pSectionName, __out PULONG pSectionSize) {
	// ��λPE�ṹ
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImageBase;
	PIMAGE_NT_HEADERS pNth = (PIMAGE_NT_HEADERS)((PUCHAR)pImageBase + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNth);


	// ��������
	for (size_t i = 0; i < pNth->FileHeader.NumberOfSections; i++) {
		PUCHAR  pSecName = &pSec[i].Name;
		if (_strnicmp(pSectionName, pSecName, IMAGE_SIZEOF_SHORT_NAME) == 0) {
			// �ҵ�����
			*pSectionSize = pSec[i].Misc.VirtualSize;
			return pSec[i].VirtualAddress;
		}
	}
	return NULL;
}

// ��λ������
PVOID SearchCode(__in PUCHAR pModuleName, __in PUCHAR pSectionName, __in PUCHAR szCode, __in ULONG szCodeSize) {
	// 1.��ȡָ��ģ�����Ϣ
	PSYSTEM_MODULE_INFORMATION pModules = NULL;
	PSYSTEM_MODULE_INFORMATION_ENTRY pModule = GetSystemModuleByName(pModuleName, &pModules);
	if (!pModule) {
		DbgPrint("not find module!");
		return NULL;
	}

	PVOID pImageBase = pModule->Base;


	ULONG sectionSize = 0;
	// ��ȡ����ƫ��
	ULONG pSectionBaseRva = GetSectionRvaByName(pImageBase, pSectionName, &sectionSize);

	// ��ʼ��ַ
	PUCHAR startAddr = !pSectionBaseRva ? (PUCHAR)pImageBase : (PUCHAR)pImageBase + pSectionBaseRva;
	// �յ��ַ
	PUCHAR endAddr = !pSectionBaseRva ? (PUCHAR)startAddr + sectionSize + pModule->Size : (PUCHAR)startAddr + sectionSize;

	// 2.����ʼ��ַ���յ��ַ֮�� ��λ���� ͨ���Ϊ? ��ͨ�����ռһ��char ���� "A?B"

	for (size_t p = startAddr; p < endAddr; p++) {
		char c = *(char*)p;
		// ƥ���ϵ�һ���ַ��������һ���ַ���ͨ���?Ҳ��Ϊƥ���ϵ�һ���ַ�
		if (c == szCode[0] || szCode[0] == '?') {
			// �ȽϺ����ַ�
			PUCHAR p1 = p; // �ڴ�ָ��
			PUCHAR p2 = szCode; // ������ָ��
			// ��¼��ƥ��ĳ���
			ULONG matchSize = 0;
			while (matchSize < szCodeSize && (p1 < endAddr) && (*p1 == *p2 || *p2 == '?')) {
				p1++;
				p2++;
				matchSize++;
			}

			if (matchSize == szCodeSize) {
				// ƥ��ɹ�
				return p;
			}
		}
	}

	return NULL;
}