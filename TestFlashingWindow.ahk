Gui, New,, Just flashing window to test against
Gui, Add, Button, x+300 y+50 w50 gQuitter, Exit

Gui, Show

Loop 999
{
    Gui, Flash
    Sleep 2000
}

Return

GuiEscape:
GuiClose:
Quitter:
ExitApp