#pragma once
#include <ntifs.h>

// 定义一些未文档化的NT结构或函数
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase; // Ptr64 Void
	PVOID EntryPoint; // Ptr64 Void
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	UCHAR FlagGroup[4];
	ULONG Flags;
	struct {
		ULONG PackagedBinary : 1;
		ULONG MarkedForRemoval : 1;
		ULONG ImageDll : 1;
		ULONG LoadNotificationsSent : 1;
		ULONG TelemetryEntryProcessed : 1;
		ULONG ProcessStaticImport : 1;
		ULONG InLegacyLists : 1;
		ULONG InIndexes : 1;
		ULONG ShimDll : 1;
		ULONG InExceptionTable : 1;
		ULONG ReservedFlags1 : 2;
		ULONG LoadInProgress : 1;
		ULONG LoadConfigProcessed : 1;
		ULONG EntryProcessed : 1;
		ULONG ProtectDelayLoad : 1;
		ULONG ReservedFlags3 : 2;
		ULONG DontCallForThreads : 1;
		ULONG ProcessAttachCalled : 1;
		ULONG ProcessAttachFailed : 1;
		ULONG CorDeferredValidate : 1;
		ULONG CorImage : 1;
		ULONG DontRelocate : 1;
		ULONG CorILOnly : 1;
		ULONG ReservedFlags5 : 3;
		ULONG Redirected : 1;
		ULONG ReservedFlags6 : 2;
		ULONG CompatDatabaseProcessed : 1;
	};
	USHORT ObsoleteLoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
	PVOID EntryPointActivationContext; // Ptr64 _ACTIVATION_CONTEXT
	PVOID Lock; // Ptr64 Void
	PVOID DdagNode; // Ptr64 _LDR_DDAG_NODE
	LIST_ENTRY NodeModuleLink;
	PVOID LoadContext; // Ptr64 _LDRP_LOAD_CONTEXT
	PVOID ParentDllBase; // Ptr64 Void
	PVOID SwitchBackContext; // Ptr64 Void
	// 这里使用 PVOID 作为占位符
	PVOID BaseAddressIndexNode; // _RTL_BALANCED_NODE
	PVOID MappingInfoIndexNode; // _RTL_BALANCED_NODE
	ULONGLONG OriginalBase; // Uint8B
	LARGE_INTEGER LoadTime; // _LARGE_INTEGER
	ULONG BaseNameHashValue;
	ULONG LoadReason; // _LDR_DLL_LOAD_REASON
	ULONG ImplicitPathOptions;
	ULONG ReferenceCount;
	ULONG DependentLoadFlags;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

NTSTATUS ObReferenceObjectByName(
	PUNICODE_STRING ObjectName, // 驱动对象名称例如 \\Driver\\PCHunter
	ULONG Attributes,			// 属性 填NULL即可
	PACCESS_STATE AccessState,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PVOID ParseContext,
	PVOID* Object
);
extern POBJECT_TYPE* IoDriverObjectType;

#define INITCODE code_set("INIT")