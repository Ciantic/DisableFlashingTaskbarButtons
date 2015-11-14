; Customizes explorer.exe by in-memory patching:
; Command line parameters Arguments:
; -NoFlashing       - Disable flashing taskbar buttons
; -NoWindowReplace  - Disable desktop changing when window activates (does nothing)
; -NoMsgBox         - Don't show message box on completion (only on errors)
; 
; This patch has been tested with Windows 10, 64bit builds: 10240, 10565, 10586
; 
; Jari Pennanen, 2015
; MIT License
; Source Code at https://github.com/Ciantic/DisableFlashingTaskbarButtons

Process,Exist,explorer.exe
explorerPid := ErrorLevel

note := "You have to restart explorer.exe to cancel the patch."

if (!explorerPid) {
    MsgBox % "Explorer is not running, unable to patch"
    ExitApp
}

user32 := DllCall("LoadLibrary", "Str", "user32", "Ptr")

memcpy(ptrAddress, ptrFrom, size) {
    return DllCall("msvcrt\memcpy_s", "UPtr", ptrAddress + 0, "Int", size, "UPtr", ptrFrom, "Int", size, "Int")
}

memcmp(ptrAddress, ptrFrom, size) {
    return DllCall("msvcrt\memcmp", "Ptr", ptrAddress, "Ptr", ptrFrom, "Int", size, "Int")
}

VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect:=0x40) {
    VarSetCapacity(oldProtect, 8, 0)
    DllCall("VirtualProtectEx", "Ptr", hProcess, "Ptr", lpAddress, "UInt", dwSize, "UInt", flNewProtect, "Ptr", &oldProtect, "Int")
    return NumGet(oldProtect, 0, "UInt")
}

ReadProcessMemoryToBuffer(ByRef toBuffer, hProcess, remoteAddress, bufferSize) {
    VarSetCapacity(toBuffer, bufferSize, 0)
    VarSetCapacity(bytesRead, 8, 0)
    DllCall("ReadProcessMemory", "Ptr", hProcess, "Ptr", remoteAddress, "Ptr", &toBuffer, "UInt", bufferSize, "Ptr", &bytesRead, "Int")
    return NumGet(bytesRead, 0, "UInt")
}

OverwriteProcessMemory(hProcess, remoteAddress, localAddress, bufferSize) {
    VarSetCapacity(bytes, 8, 0)
    DllCall("WriteProcessMemory", "Ptr", hProcess, "Ptr", remoteAddress, "Ptr", localAddress, "UInt", bufferSize, "Ptr", &bytes, "Int")
    return NumGet(bytes, 0, "UInt")
}

WriteProcessMemoryEmpty(hProcess, localAddress, bufferSize) {
    remoteAddress := DllCall("VirtualAllocEx", "Ptr", hProcess, "Int", 0, "UInt", bufferSize, "Int", 0x1000, "Int", 0x40, "Ptr")
    VarSetCapacity(bytes, 8, 0)
    DllCall("WriteProcessMemory", "Ptr", hProcess, "Ptr", remoteAddress, "Ptr", localAddress, "UInt", bufferSize, "Ptr", &bytes, "Int")
    if (NumGet(bytes, 0, "UInt") != bufferSize) {
        return 0
    }
    return remoteAddress
}

FreeProcessMemory(hProcess, remoteAddress, size) {
    return DllCall("VirtualFreeEx", "Ptr", hProcess, "Ptr", remoteAddress, "UInt", size, "Int", 0x8000, "Int")
}

StrPad(Str, PadChar, PadLen, Left=1) { 
   StringLen, sLen, str 
   if (sLen >= PadLen) 
      return str 
   sDif := PadLen - sLen 
   strPad := "" 
   Loop, %sDif% { 
      strPad := strPad . PadChar 
   } 
   Retval := "" 
   If (Left=1) { 
      Retval := strPad . Str 
   } else { 
      Retval := str . strPad 
   } 
   return Retval 
} 

Hex2Dec(hexStr) {
    static U := A_IsUnicode  ? "wcstoui64_l" : "strtoui64"
    return, DllCall("msvcrt\_" U, "Str", hexStr, "Uint",0, "Int", 16, "CDECL Int64")
}

Dec2Hex(dec) {
    static U := A_IsUnicode ? "w" : "a"
    VarSetCapacity(S,65,0)
    DllCall("msvcrt\_i64to" U, "Int64", dec, "Str",S, "Int", 16)
    StringUpper, S, S
    if (Mod(StrLen(S), 2) = 1)
        S := "0" . S
    return S
}
 
HexStringToBufferObject(str, repeat := 1) {
    originalStr := str
    Loop, % repeat - 1  {
        str .= " " . originalStr
    }
    hexString := Trim(RegExReplace(str, "\s+", " "))
    StringUpper, hexString, hexString
    bytes := StrSplit(hexString, " ")
    res := { "str" : hexString, "buffer" : "", "ptr" : "", "size" : bytes.MaxIndex() }
    res.SetCapacity("buffer", bytes.MaxIndex() + 2)
    res.ptr := res.GetAddress("buffer")
    for k, hex in bytes {
        NumPut(Hex2Dec(hex), res.ptr + 0, k - 1, "UChar")
    }
    return res
}

ReadBufferObjectFrom(ptrAddress, bufferSize) {
    hexString := ""
    res := { "str" : "", "buffer" : "", "ptr" : "", "size" : bufferSize }
    res.SetCapacity("buffer", bufferSize)
    res.ptr := res.GetAddress("buffer")
    memcpy(res.ptr, ptrAddress, bufferSize)
    Loop % bufferSize {
        hexString .= Dec2Hex(NumGet(res.ptr + 0, A_Index - 1, "UChar"))
 
        if (A_Index != bufferSize) {
            hexString .= " "
        }
    }
    res.str := hexString
    return res
}

; Turns decimal to assembly hexes (reversed)
Dec2Asm(decimal, byteLen) {
    result := ""
    hexes := SubStr(Dec2Hex(decimal), - byteLen * 2)
    hexes := StrPad(hexes, "0", byteLen * 2, 1)
    index := Floor(StrLen(hexes) / 2)
    ; Reverse bytes
    Loop % index {
        result .= SubStr(hexes, - ((A_Index - 1) * 2 + 1), 2)
        if (A_Index != index)
            result .= " "
    }
    return result
}

; 2 or 5 byte relative jump
JmpAsm(decimalOffset) {
    jumpBytes := Abs(decimalOffset) > 127 ? 4 : 1
    decimalOffset -= jumpBytes + 1
    return (jumpBytes = 4 ? "E9 " : "EB ") . Dec2Asm(decimalOffset, jumpBytes)
}

; Tested against x64dbg with values:
;~ MsgBox % "JMP:"
    ;~ . "`n(+1603214) E9 89 76 18 00 = " . JmpAsm(0x00007FF73DD00F04 - 0x00007FF73DB79876) . ""
    ;~ . "`n (-1603214) E9 6D 89 E7 FF = " . JmpAsm(0x00007FF73DB79876 - 0x00007FF73DD00F04) . ""
    ;~ . "`n JMP short:"
    ;~ . "`n(+5) EB 03 = " . JmpAsm(0x00007FF73DD00F86 - 0x00007FF73DD00F81) . ""
    ;~ . "`n (-5) EB F9 = " . JmpAsm(0x00007FF73DD00F81 - 0x00007FF73DD00F86)

; Shell tray (task switcher grand parent window)
shellTrayHwnd := DllCall("FindWindow", Str, "Shell_TrayWnd", Int, 0)

if (shellTrayHwnd = 0) {
    MsgBox % "Shell Tray window not found"
    ExitApp
}

; Find task switcher handle
taskSwitcherHwnd := 0
EnumChildWindowsCallback(Hwnd, lParam) {
    global taskSwitcherHwnd
    WinGetClass, Class, ahk_id %Hwnd%
    if (Class = "MSTaskSwWClass") {
        taskSwitcherHwnd := Hwnd
    }
    return true
}
DllCall("EnumChildWindows", UInt, shellTrayHwnd, UInt, RegisterCallback("EnumChildWindowsCallback", "Fast"), UInt, 0)

if (taskSwitcherHwnd = 0) {
    MsgBox % "Task Switcher not found"
    ExitApp
}

getWindowLongPtrWAddr := DllCall("GetProcAddress", "Ptr", user32, "AStr", "GetWindowLongPtrW", "Ptr")
if (!getWindowLongPtrWAddr) {
    MsgBox % "Unable to retrieve GetWindowLongPtrW address"
    ExitApp
}

hProcess := DllCall("OpenProcess", "UInt", 0x001F0FFF, "Int", 0, "UInt", explorerPid, "Ptr")

GetWindowLongPtrFuncAsm := Dec2Asm(getWindowLongPtrWAddr, 8)
GetWindowLongPtrFunc := HexStringToBufferObject(""
    . " 40 53"                            ; push        rbx
    . " 48 83 EC 20"                      ; sub         rsp,20h
    . " 8B 51 08"                         ; mov         edx,dword ptr [rcx+8]
    . " 48 8B D9"                         ; mov         rbx,rcx
    . " 48 8B 09"                         ; mov         rcx,qword ptr [rcx]
    . " 48 B8 " . GetWindowLongPtrFuncAsm ; movabs rax, [GetWindowLongPtrW]
    . " FF D0"                            ; call rax
    . " 48 89 43 10"                      ; mov         qword ptr [rbx+10h],rax
    . " 48 83 C4 20"                      ; add         rsp,20h
    . " 5B"                               ; pop         rbx
    . " C3"                               ; ret
    . " CC"                               ; alignment?
    . "")


funcAddr := WriteProcessMemoryEmpty(hProcess, GetWindowLongPtrFunc.ptr, GetWindowLongPtrFunc.size)
if (!funcAddr) {
    MsgBox % "Could not allocate or write a function to process memory"
    ExitApp
}

paramsSize := 24
VarSetCapacity(params, paramsSize, 0)
NumPut(taskSwitcherHwnd, params, 0, "UPtr")
NumPut(-4, params, 8, "Int")
paramsAddr := WriteProcessMemoryEmpty(hProcess, &params, paramsSize)
if (!paramsAddr) {
    FreeProcessMemory(hProcess, funcAddr, GetWindowLongPtrFunc.size)
    FreeProcessMemory(hProcess, paramsAddr, paramsSize)
    MsgBox % "Could not allocate or write parameters to process memory"
    ExitApp
}

hThread := DllCall("CreateRemoteThread", "Ptr", hProcess, "Int", 0, "Int", 0, "Ptr", funcAddr, "Ptr", paramsAddr, "Int", 0, "Int", 0, "Ptr") 
if (!hThread) {
    FreeProcessMemory(hProcess, funcAddr, GetWindowLongPtrFunc.size)
    FreeProcessMemory(hProcess, paramsAddr, paramsSize)
    MsgBox % "Could not create remote thread"
    ExitApp
}

DllCall("WaitForSingleObject", "Ptr", hThread, "UInt", 0xFFFFFFFF)

; EXIT CODE:
;~ VarSetCapacity(exitCode, 8, 0)
;~ DllCall("GetExitCodeThread", "Ptr", hThread, "UPtr", &exitCode, "UInt")
;~ MsgBox % "Thread: " . hThread . " res " . exitRes . " code " . ReadBufferObjectFrom(&exitCode, 8).str

; Read WndProc address from the params
ReadProcessMemoryToBuffer(paramsOut, hProcess, paramsAddr, paramsSize)
taskSwitcherWndProcAddr := NumGet(paramsOut, 16, "Ptr")

FreeProcessMemory(hProcess, funcAddr, GetWindowLongPtrFunc.size)
FreeProcessMemory(hProcess, paramsAddr, paramsSize)

if (taskSwitcherWndProcAddr == 0) {
    MsgBox % "Task Switcher WinProc not found"
    ExitApp
}

expectedBufferAddr := taskSwitcherWndProcAddr - 7
expectedBuffer := HexStringToBufferObject("CC CC CC CC CC CC CC 48 89 5C 24 18 48 89 6C 24 20 57 41 56 41 57")
ReadProcessMemoryToBuffer(actualBuffer, hProcess, expectedBufferAddr, expectedBuffer.size)
if (memcmp(&actualBuffer, expectedBuffer.ptr, expectedBuffer.size) != 0) {
    actualBufferHex := ReadBufferObjectFrom(&actualBuffer, expectedBuffer.size)
    if (RegExMatch(actualBufferHex.str, "CC .. .. .. .. .. CC")) {
        if (%0% != "-NoMsgBox") {
            MsgBox % "Explorer.exe is already patched. " note
        }
    } else {
        MsgBox % "Task Switcher WinProc does not match:`r`n"
            . actualBufferHex.str
    }
    ExitApp
}

; The patch for WndProc
jmpDownwardsAddr := taskSwitcherWndProcAddr - 6
jmpUpwardsAddr := taskSwitcherWndProcAddr + 11
jmpContinueAddr := taskSwitcherWndProcAddr + 13 ; Next command after push r14
jmpUpwards := HexStringToBufferObject(JmpAsm(-11 - 6)) ; Replaces "push r14" (41 56) in the WndProc
/*
00007FF73DD00102 | 49 81 F8 06 80 00 00     | cmp r8,8006                             |
00007FF73DD00109 | 74 06                    | je explorer.7FF73DD00111                |
00007FF73DD0010B | 49 83 F8 13              | cmp r8,13                               |
00007FF73DD0010F | 75 0C                    | jne explorer.7FF73DD0011D               |
00007FF73DD00111 | 48 81 FA 2B C0 00 00     | cmp rdx,C02B                            |
00007FF73DD00118 | 75 03                    | jne explorer.7FF73DD0011D               |
00007FF73DD0011A | 48 31 D2                 | xor rdx,rdx                             |
00007FF73DD0011D | 41 56                    | push r14                                |
00007FF73DD0011F | E9 69 97 E7 FF           | jmp explorer.7FF73DB7988D               |
*/
patch := HexStringToBufferObject("" 
  . "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " ; 15 bytes before the patch oughta be enough
  . "90 90 90 90 90 90 "    ; 6 x nop (saturates the zeroed area even if it hits second byte)
  . "49 81 F8 06 80 00 00 " ; cmp r8, 0x8006  (0x8006 = HSHELL_FLASH)
  . "74 06 "                ; je +6 bytes     (to cmp c023b)
  . "49 83 F8 13 "          ; cmp r8,0x13     (0x13 = HSHELL_WINDOWREPLACED)
  . "75 0C "                ; jne +12 bytes   (to push r14)
  . "48 81 FA 2B C0 00 00 " ; cmp rdx, 0xC02B (0xC02B = SHELLHOOK)
  . "75 03 "                ; jne +3 bytes    (to push r14)
  . "48 31 D2 "             ; xor rdx, rdx    (empty message)
  . "41 56 "                ; push r14        (resume)
  . "XX XX XX XX XX "       ; jmp to Continue Addr (replaced later)
  . "00 00 00 00 00 00 00 00 00 00 00 00"
  . "")

emptyBeginAddr := taskSwitcherWndProcAddr
patchCmp := HexStringToBufferObject(SubStr(patch.str, 1, 44 * 3)) ; Until XX (44th byte)
VarSetCapacity(localTempBuffer, patchCmp.size, 0)
VarSetCapacity(emptyBuffer, patch.size, 0)

foundEmptyArea := false
loopCount := Floor(1855487 / patch.size)
Loop, %loopCount% {
    emptyBeginAddr += patch.size
    ReadProcessMemoryToBuffer(localTempBuffer, hProcess, emptyBeginAddr, patch.size)
    if (memcmp(&localTempBuffer, &emptyBuffer, patch.size) = 0) or (memcmp(&localTempBuffer, patchCmp.ptr, patchCmp.size) = 0) {
        foundEmptyArea := true
        Break
    }
}

if (!foundEmptyArea) {
    MsgBox % "Can't find empty area for the patch :("
    ExitApp
}

; Calculate the jmp to the begin of patch (15 x 0, 6 x nop in the patch)
patchBeginAddr := emptyBeginAddr + 15 + 6
patchEndAddr := emptyBeginAddr + (InStr(patch.str, "XX XX XX XX XX") / 3) ; XX XX XX XX XX
patchBeginOffset := patchBeginAddr - jmpDownwardsAddr
jmpDownwards := HexStringToBufferObject(JmpAsm(patchBeginOffset))
jmpContinueOffset := jmpContinueAddr - patchEndAddr
jmpContinue := HexStringToBufferObject(JmpAsm(jmpContinueOffset))
patch := HexStringToBufferObject(StrReplace(patch.str, "XX XX XX XX XX", jmpContinue.str))

prot := VirtualProtectEx(hProcess, jmpDownwardsAddr, emptyBeginAddr + patch.size - jmpDownwardsAddr)
OverwriteProcessMemory(hProcess, jmpDownwardsAddr, jmpDownwards.ptr, jmpDownwards.size)
OverwriteProcessMemory(hProcess, emptyBeginAddr, patch.ptr, patch.size)
OverwriteProcessMemory(hProcess, jmpUpwardsAddr, jmpUpwards.ptr, jmpUpwards.size)
VirtualProtectEx(hProcess, jmpDownwardsAddr, emptyBeginAddr + patch.size - jmpDownwardsAddr, prot)

DllCall("CloseHandle", "Ptr", hProcess , "Int")

if (%0% != "-NoMsgBox") {
    MsgBox % "Explorer.exe is now patched. " note
}
ExitApp