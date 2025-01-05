.code
PUBLIC GetGDTR
GetGDTR PROC
    sgdt [rdi]
    ret
GetGDTR ENDP
END
