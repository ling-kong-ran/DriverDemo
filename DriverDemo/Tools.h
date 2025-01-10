#include "NtDef.h"

PDRIVER_OBJECT GetDriverObjectByName(__in PCWSTR name);


PSYSTEM_MODULE_INFORMATION_ENTRY GetSystemModuleByName(__in PUCHAR moduleName, __out PSYSTEM_MODULE_INFORMATION* pModulesBuffer);


