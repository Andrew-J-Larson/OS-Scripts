set Args = WScript.Arguments
source = Args(0)
target = Args(1)
set fso = CreateObject("Scripting.FileSystemObject")
if not fso.FolderExists(target) Then
   fso.CreateFolder(target)
End If
set objShell = CreateObject("Shell.Application")
set itemsInZip = objShell.NameSpace(source).items
objShell.NameSpace(target).CopyHere(itemsInZip),4
set fso = Nothing
set objShell = Nothing
