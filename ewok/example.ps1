add-type -AssemblyName microsoft.VisualBasic
add-type -AssemblyName System.Windows.Forms
Calc 
start-sleep -Milliseconds 500
[Microsoft.VisualBasic.Interaction]::AppActivate("c:\Windows\SysWOW64\calc.exe")
[System.Windows.Forms.SendKeys]::SendWait("31337")
#
