; In-memory patches running explorer.exe to disable flashing taskbar buttons
; 
; Jari Pennanen, 2015
; MIT License

nSize := VarSetCapacity(processPath, 512, 0)
DllCall("GetModuleFileName", "Ptr", 0, "Ptr", &processPath, "UInt", nSize)
SplitPath, processPath,,,,processName, 

TestedVersions := "This patch has been tested with Windows 10, 64bit builds: 10240, 10565"

if (processName != "explorer") {
    if (not FileExist("AutoHotkey.dll")) or (not FileExist("RemoteThreader.exe")) {
        MsgBox % "Unable to execute, one or more of the following dependencies are missing:`n`n"
            . " - AutoHotkey.dll get from`nhttps://github.com/hotKeyIt/ahkdll-v1-release/ (file x64w/AutoHotkey.dll)`n`n"
            . " - VS 2015 C++ runtimes at`nhttps://www.microsoft.com/en-us/download/details.aspx?id=48145`n`n"
            . " - RemoteThreader.exe found at`nhttps://github.com/Ciantic/RemoteThreader (file x64/Release/RemoteThreader.exe)`n`n"
            . "Place AutoHotkey.dll and RemoteThreader.exe in same directory as this script, install VS 2015 C++ runtimes"
        ExitApp
    }
    ; Running outside the explorer
    Run, RemoteThreader.exe explorer.exe AutoHotkey.dll ahktextdll "#include %A_ScriptFullPath%", , Hide
    sleep, 1500
    Run, RemoteThreader.exe explorer.exe AutoHotkey.dll ahkterminate, , Hide
    sleep, 300
    Run, RemoteThreader.exe explorer.exe AutoHotkey.dll, , Hide
    FileRead, Message, % A_ScriptDir . "\commands.log"
    MsgBox % Message
    ExitApp
}

LogFile := FileOpen(A_ScriptDir . "\commands.log", "w")
LogFile.Write(TestedVersions . "`r`n`r`n")

virtualProtect(ptrAddress, size, protection:=0x40) { 
    ; 0x40 = PAGE_EXECUTE_READWRITE
    return DllCall("kernel32\VirtualProtect", Ptr, ptrAddress, UPtr, size, UInt, protection, Int)
}

memcpy(ptrAddress, ptrFrom, size) {
    return DllCall("msvcrt\memcpy_s", "Ptr", ptrAddress, "Int", size, "Ptr", ptrFrom, "Int", size, "Int")
}

memset(ptrAddress, val, n:=1) {
    return DllCall("msvcrt\memset", "Ptr", ptrAddress, "Int", val, "UInt", n, "Ptr")
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
    hexString := str
    StringUpper, hexString, hexString
    bytes := StrSplit(str, " ")
    res := { "str" : hexString, "buffer" : "", "ptr" : "", "size" : bytes.MaxIndex() }
    res.SetCapacity("buffer", bytes.MaxIndex() + 2)
    res.ptr := res.GetAddress("buffer")
    for k, hex in bytes {
        NumPut(Hex2Dec(hex), res.ptr + 0, k - 1, "UChar")
    }
    return res
}
 
GetBufferObjectFrom(ptrAddress, bufferSize) {
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

; 2 or 5 byte relative jump
JmpAsm(decimalOffset) {
    jumpBytes := Abs(decimalOffset) > 127 ? 4 : 1
    decimalOffset -= jumpBytes + 1
    result := ""
    hexes := SubStr(Dec2Hex(decimalOffset), - jumpBytes * 2)
    hexes := StrPad(hexes, "0", jumpBytes * 2, 1)
    index := Floor(StrLen(hexes) / 2)
    ; Reverse bytes
    Loop % index {
        result .= SubStr(hexes, - ((A_Index - 1) * 2 + 1), 2)
        if (A_Index != index)
            result .= " "
    }
    return (jumpBytes = 4 ? "E9 " : "EB ") . result
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
    LogFile.Write("Shell Tray window not found")
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
    LogFile.Write("Task Switcher not found")
    ExitApp
}

; Get task switcher WndProc
taskSwitcherWndProcAddr := DllCall("user32\GetWindowLongPtrW", Ptr, taskSwitcherHwnd, Int, -4, Ptr)

if (taskSwitcherWndProcAddr == 0) {
    LogFile.Write("Task Switcher WinProc not found")
    ExitApp
}

expectedBufferAddr := taskSwitcherWndProcAddr - 7
expectedBuffer := HexStringToBufferObject("CC CC CC CC CC CC CC 48 89 5C 24 18 48 89 6C 24 20 57 41 56 41 57")
actualBuffer := GetBufferObjectFrom(expectedBufferAddr, expectedBuffer.size)
if (actualBuffer.str != expectedBuffer.str) {
    LogFile.Write("Task Switcher WinProc does not match:`r`n"
        . actualBuffer.str
        . "`r`n`r`nHave you run the patch already?")
    ExitApp
}

; The patch for WndProc
jmpDownwardsAddr := taskSwitcherWndProcAddr - 6
jmpUpwardsAddr := taskSwitcherWndProcAddr + 11
jmpContinueAddr := taskSwitcherWndProcAddr + 13 ; Next command after push r14
jmpUpwards := HexStringToBufferObject(JmpAsm(-11 - 6)) ; Replaces "push r14" (41 56) in the WndProc

patch := HexStringToBufferObject("" 
  . "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " ; 15 bytes before the patch oughta be enough
  . "90 90 90 90 90 90 "    ; 6 x nop (saturates the zeroed area even if it hits second byte)
  . "49 81 F8 06 80 00 00 " ; cmp r8, 0x8006 (HSHELL_FLASH)
  . "75 0C "                ; jne +12 bytes
  . "48 81 FA 2B C0 00 00 " ; cmp rdx, 0xC02B (SHELLHOOK)
  . "75 03 "                ; jne +3 bytes
  . "48 31 D2 "             ; xor rdx, rdx
  . "41 56 "                ; push r14
  . "XX XX XX XX XX "       ; jmp to Continue Addr (replaced later)
  . "00 00 00 00 00 00 00 00 00 00 00 00"
  . "")
   
emptyBeginAddr := taskSwitcherWndProcAddr
emptyBuffer := HexStringToBufferObject("00", patch.size)
Loop, 1615 {
    emptyBeginAddr += 512
    readBuffer := GetBufferObjectFrom(emptyBeginAddr, emptyBuffer.size)
    if (emptyBuffer.str = readBuffer.str) or (readBuffer.str = patch.str) {
        break
    }
}

; Calculate the jmp to the begin of patch (15 x 0, 6 x nop in the patch)
patchBeginAddr := emptyBeginAddr + 15 + 6
patchEndAddr := patchBeginAddr + 23 ; XX XX XX XX XX
patchBeginOffset := patchBeginAddr - jmpDownwardsAddr
jmpDownwards := HexStringToBufferObject(JmpAsm(patchBeginOffset))
jmpContinueOffset := jmpContinueAddr - patchEndAddr
jmpContinue := HexStringToBufferObject(JmpAsm(jmpContinueOffset))
patch := HexStringToBufferObject(StrReplace(patch.str, "XX XX XX XX XX", jmpContinue.str))

virtualProtect(expectedBufferAddr, 1599709 * 2)
memcpy(emptyBeginAddr, patch.ptr, patch.size)
memcpy(jmpDownwardsAddr, jmpDownwards.ptr, jmpDownwards.size)
memcpy(jmpUpwardsAddr, jmpUpwards.ptr, jmpUpwards.size)
LogFile.Write("WndProc: 0x" . Dec2Hex(taskSwitcherWndProcAddr) . "`r`n")
LogFile.Write("Patch detour at: 0x" . Dec2Hex(patchBeginAddr) . "`r`n")
LogFile.Write("Patch done!")
ExitApp