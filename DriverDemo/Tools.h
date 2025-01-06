#include "NtDef.h"

PDRIVER_OBJECT GetDriverObjectByName(PCWSTR name);
VOID HideMySelf(PVOID StartContext);

extern HANDLE ptHandle;
VOID OnDriverInit();