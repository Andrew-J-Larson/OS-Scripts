set Args = WScript.Arguments
source = Args(0)
while Right(source, 1) = "\"
    source = Mid(source, 1, Len(source) - 1)
wend
target = Args(1)
set fso = CreateObject("Scripting.FileSystemObject")
set zip = fso.OpenTextFile(target, 2, vbtrue)
zip.Write "PK" & Chr(5) & Chr(6) & String(18, Chr(0))
zip.Close
set zip = nothing
set fso = nothing
set app = CreateObject("Shell.Application")
set sourceFolderObj = app.NameSpace(source)
set targetFolderObj = app.NameSpace(target)
for each item in sourceFolderObj.Items
  itemPath = source & "\" & item.Name
  copyItem = false
  if itemPath <> target then
    if item.IsFolder then
      if item.GetFolder.Items().Count = 0 then
      else
        copyItem = true
      end if
    else
      copyItem = true
    end if
  end if
  if copyItem then
    targetFolderObj.CopyHere item,4
    while (targetFolderObj.ParseName(item.Name) is nothing)
      WScript.Sleep 1
    wend
  end If
next
set targetFolderObj = nothing
set sourceFolderObj = nothing
set app = nothing
