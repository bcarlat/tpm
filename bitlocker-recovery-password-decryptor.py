#!/usr/bin/env python3
#
# Bitlocker Recovery Password Decryptor 
#    by Pascal Gujer (@pascal_gujer)
#
# requires pycryptodome (pip3 install pycryptodome)

import sys
import os.path
import re
import subprocess
from Crypto.Cipher import AES

############################################################
# Banner                                                   #
############################################################
def banner():
   print("########################################################################################")
   print("#                                                                                      #")
   print("#                       BitLocker Recovery Password Decryptor                          #")
   print("#                                                                                      #")
   print("# by Pascal Gujer (@pascal_gujer)                                                v1.1  #")
   print("########################################################################################")
   print()

############################################################
# Help                                                     #
############################################################
def help():
   # Display Help
   banner()
   print("This script decrypts the encrypted recovery password from a given BitLocker drive")
   print("with the given Volume Master Key (VMK) and prints the result in the official")
   print("recovery password format.")
   print()
   print("'dislocker-metadata' is required to be in path")
   print()
   print("Syntax: bitlocker-recovery-password-decryptor {VMK as hex} {path to BitLocker partition}")
   print()
   exit()

def stringsplitter(string, splitsize):
    return (string[0+i:splitsize+i] for i in range(0, len(string), splitsize))

############################################################
# Main program                                             #
############################################################
def main():
   # check if all arguments are supplied, else show help
   if(len(sys.argv)!=3): help()
   
   banner()
   
   # get dislocker-metadata
   print("Extracting BitLocker key material with dislocker-metadata...")
   bitlocker_partition=sys.argv[2]
   os_command = "dislocker-metadata -V " + bitlocker_partition
   try:
       dislocker_metadata = subprocess.check_output(os_command.split()).decode(sys.stdout.encoding).splitlines()
   except:
       print('ABORT: \"',os_command, '\" failed.', sep='')
       exit('       Please check if the supplied partition is a proper BitLocker partition')
   print("Parsing output...")
   print()
   for index, line in enumerate(dislocker_metadata):
       if "Datum value type: 3" in line:
           for i in range(20):
               if " Nonce:" in dislocker_metadata[index+i]:
                   try:
                       nonce=bytes().fromhex(''.join(dislocker_metadata[index+i+1].split()[6:]))
                       print("Nonce:                 ",nonce.hex())
                   except:
                       exit('ABORT: Nonce extraction failed')
               elif " MAC:" in dislocker_metadata[index+i]:
                   try:
                       mac=bytes().fromhex(''.join(dislocker_metadata[index+i+1].split()[6:]))
                       print("MAC:                   ",mac.hex())
                   except:
                       exit('ABORT: MAC extraction failed')
               elif " Payload:"  in dislocker_metadata[index+i]:
                   try:
                       rek_encrypted=bytes().fromhex(''.join(dislocker_metadata[index+i+1].split()[7:]).replace('-','')+''.join(dislocker_metadata[index+i+2].split()[7:]).replace('-',''))
                       print("Encrypted Recovery Password:",rek_encrypted.hex())
                   except:
                       exit('ABORT: Encrypted recovery password extraction failed')
   
   # sanitize & check VMK
   input_vmk=sys.argv[1]
   if len(input_vmk) != 64:
       exit('ABORT: VMK length mismatch!')
   try:
       vmk=bytes.fromhex(input_vmk)
   except:
       exit('ABORT: VMK format mismatch!')
   print()
   print("VMK:                   ", vmk.hex())
   
   print()
   print("Decrypting recovery password...")
   cipher = AES.new(vmk, AES.MODE_CCM, nonce)
   rek_decrypted = cipher.decrypt(rek_encrypted)
   try:
       cipher.verify(mac)
       print("The decrypted recovery password is authentic:")
       print(rek_decrypted.hex(),'\n')
       rek_human=[]
       for item in list(stringsplitter(rek_decrypted.hex()[24:],4)):
           i=(bytes.fromhex(item)[0]+(bytes.fromhex(item)[1]*256))*11
           rek_human.append(f'{i:06d}')
       print("[+] Sucessfully retrieved the BitLocker Recovery Password in human readable format: ")
       print()
       print("            ", end = '')
       print(*rek_human, sep='-')
       print()
   except ValueError:
       exit('ABORT: VMK incorrect or data corrupted')
   
      
if __name__ == '__main__':
   main()

