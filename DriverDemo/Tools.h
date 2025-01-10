#include "NtDef.h"

PDRIVER_OBJECT GetDriverObjectByName(__in PCWSTR name);


PVOID GetSystemModuleByName(__in PUCHAR moduleName, __out PSYSTEM_MODULE_INFORMATION* pModulesBuffer);