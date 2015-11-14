Gui, New,, Activate window after 4 secs of click
Gui, Add, Button, x+300 y+50 w50 gActivate, Activate

Gui, Show

Return

Activate:
Sleep 4000
WinActivate
Return

GuiEscape:
GuiClose:
ExitApp