
Disable flashing taskbar buttons (64 bit)
=========================================

Injects a autohotkey inside running explorer.exe, in-memory patches the flashing taskbar button feature in the explorer.exe, and removes autohotkey from the explorer.exe memory.

Notice that this works just like viruses does by modifying memory area of explorer.exe, and maybe detected as virus.

Dependencies:

* AutoHotkey (v1) of course to run the script
* AutoHotkey.dll found at : https://github.com/hotKeyIt/ahkdll-v1-release/ (file x64w/AutoHotkey.dll)
* VS 2015 C++ runtimes at : https://www.microsoft.com/en-us/download/details.aspx?id=48145
* RemoteThreader.exe found at : https://github.com/Ciantic/RemoteThreader (file x64/Release/RemoteThreader.exe)

Place AutoHotkey.dll and RemoteThreader.exe in the same directory as this script.

You can try if it worked using TestFlashingWindow.ahk, it just creates a window which flashes continuously.


Notes
---------

MIT Licensed, see LICENSE.txt
Jari Pennanen, 2015