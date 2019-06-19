
Disable flashing taskbar buttons (64 bit)
=========================================

Modifies task switcher to ignore taskbar button flashing.

Notice that this works just like viruses does by modifying memory area of explorer.exe, and maybe detected as virus. Another interesting note is that this does not inject a DLL to explorer.exe memory, just a function I've typed as assembly in the AutoHotkey file.

Run with command line parameter -NoMsgBox if you don't want completion dialog (errors always shows the message box.)

Dependencies:

* AutoHotkey (v1) of course to run the script

You can try if it worked using TestFlashingWindow.ahk, it just creates a window which flashes continuously.

Tested with Windows 10 64bit version 1903 (18362.175, 1/2019)

Notes
---------

MIT Licensed, see LICENSE.txt
Jari Pennanen, 2015-2019