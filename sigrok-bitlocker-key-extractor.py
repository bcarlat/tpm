#!/usr/bin/env python3
#
# BitLocker Key Extractor from Sigrok SPI or LPC Annotations
#    by Pascal Gujer (@pascal_gujer)

import sys
import os.path
import re

############################################################
# Banner                                                   #
############################################################
def banner():
   print("##############################################################################")
   print("#                                                                            #")
   print("#                      Sigrok BitLocker Key Extractor                        #")
   print("#                                                                            #")
   print("# by Pascal Gujer (@pascal_gujer)                                      v1.0  #")
   print("##############################################################################")
   print()

############################################################
# Help                                                     #
############################################################
def help():
   # Display Help
   banner()
   print("This script extracts the BitLocker VMK from a given text file containing the")
   print("decoded TPM SPI or LPC messages extracted from PulseView or Sigrok.")
   print("This text file can be created by right clicking on the SPI decoder in PulseView")
   print("and selecting 'Export all annotations' or by clicking on the save icon in the")
   print("'Protocol List Viewer' in DSView and selecting text files.")
   print()
   print("Syntax: sigrok-bitlocker-key-extractor {'LPC' or 'SPI'} {path to annotations file} {samplerate optional)}")
   print()
   exit()

############################################################
# SPI Parser                                               #
############################################################
def spi(filepath):
   spi_annotations = open(filepath, "r")
   
   miso_transfers=""
   mosi_transfers=""
   for line in spi_annotations:
      # Extract all MISO transfer data
      if "SPI: MISO transfer:" in line:
         miso_transfers+=line
      # Extract all MOSI read commands of TPM_DATA_FIFO_0
      elif "SPI: MOSI transfer: 80 D4 00 24 00 00" in line:
         mosi_transfers+=line
   
   miso_transfers=miso_transfers.splitlines()
   mosi_transfers=mosi_transfers.splitlines()
   TPM_DATA_FIFO_0=""
   TPM_DATA_FIFO_0_transactions=[]
   
   # Iterate through MOSI read commands of TPM_DATA_FIFO_0
   for mosi_line in mosi_transfers:
      for miso_line in miso_transfers:
         # Search for the corresponding answer
         mosi_pattern="^"+mosi_line.split()[0]
         if re.search(mosi_pattern, miso_line):
            TPM_DATA_FIFO_0_transactions.append(miso_line)
            TPM_DATA_FIFO_0+=miso_line.split()[9]
            break
   return TPM_DATA_FIFO_0, TPM_DATA_FIFO_0_transactions

############################################################
# LPC Parser                                               #
############################################################
def lpc(filepath):
   with open(filepath, "r") as lpc_annotations:
      TPM_DATA_FIFO_0=''
      TPM_DATA_FIFO_0_transactions=[]
      
      for line in lpc_annotations:
         # Check for TPM START
         if "TPM" in line:
            cycle_type=next(lpc_annotations)
            if "Cycle type: I/O read" in cycle_type:
               address=next(lpc_annotations)
               if "Address: 0x0024" in address:
                  tar_cycle_0=next(lpc_annotations)
                  if "TAR, cycle 0: 1111" in tar_cycle_0:
                     tar_cycle_1=next(lpc_annotations)
                     if "TAR, cycle 1: 1111" in tar_cycle_1:
                        sync_cycle=next(lpc_annotations)
                        if "SYNC, cycle 0: 0000" in sync_cycle:
                           data_cycle=next(lpc_annotations)
                           TPM_DATA_FIFO_0_transactions.append(data_cycle)
                           data_byte=data_cycle.split()[len(data_cycle.split())-1][2:]
                           TPM_DATA_FIFO_0+=data_byte
                        else:
                           print("===================================================")
                           print("====================== ERROR ======================")
                           print("WRONG SYNC CYCLE: ", sync_cycle)
                           print(next(lpc_annotations))
                           print(next(lpc_annotations))
                           print()
                           print("Try to increase samplerate, this might help...")
                           print("===================================================")
                     else:
                        print("===================================================")
                        print("====================== ERROR ======================")
                        print("WRONG TAR_1 CYCLE: ", tar_cycle_1)
                        print(next(lpc_annotations))
                        print(next(lpc_annotations))
                        print()
                        print("Try to increase samplerate, this might help...")
                        print("===================================================")
                  else:
                     print("===================================================")
                     print("====================== ERROR ======================")
                     print("WRONG TAR_0 CYCLE: ", tar_cycle_0)
                     print(next(lpc_annotations))
                     print(next(lpc_annotations))
                     print(next(lpc_annotations))
                     print()
                     print("Try to increase samplerate, this might help...")
                     print("===================================================")
   return TPM_DATA_FIFO_0, TPM_DATA_FIFO_0_transactions

############################################################
# Main program                                             #
############################################################
def main():
   # check if all arguments are supplied, else show help
   if len(sys.argv)>4:
       help()       
   elif len(sys.argv)==4:
       try:
           samplerate=int(sys.argv[3])
       except:
           help()
   elif len(sys.argv)==3:
       samplerate=0
   elif len(sys.argv)<3:
       help()
   filepath=sys.argv[2]
   banner()
   
   # check if file exists
   if(not os.path.isfile(filepath)):
      print("File does not exist!")
      exit();
   
   try:
       if sys.argv[1] == 'SPI':
           print("Processing SPI transactions...")
           TPM_DATA_FIFO_0, TPM_DATA_FIFO_0_transactions = spi(filepath)
       elif sys.argv[1] == 'LPC':
           print("Processing LPC transactions...")
           TPM_DATA_FIFO_0, TPM_DATA_FIFO_0_transactions = lpc(filepath)
       else:
           help()
   except:
       print("[-] Something went wrong. Please check your input files.")
       help()
   
   # BitLocker VMK regex
   regex = r"(2c00000001000[0-1]000[0-5]200000)([0-9a-f]{64})"
   # You might try this looser regex if you have bad data with bitflips and want to do some analysis.
   # regex = r"(2C0000000[0-9A-F]{15})([0-9A-F]{64})"
   match = re.search(regex, TPM_DATA_FIFO_0, re.IGNORECASE)
   
   if not match:
       # No match has been found
       print("[-] Sorry, the BitLocker key was not found. Possible issues are:")
       print("     - Ground: Check your connection to ground (GND) - this is very important ;)")
       print("     - Wiring: Check your wiring and perform a continuity check on the connections")
       print("     - Wiring: Keep the wires as short as possible")
       print("     - Samplerate: Try to increase the samplerate. We had good results with >=250 MHz")
       print("     - Decoding: Check your decoders settings, have an eye on the channel numbers")
       print("     - Export: Export all annotations, not just the visible area")
       print()
       print("Good Luck!")
       print()
       exit(1)
   
   # Print where to find the VMK in the data (timewise)
   # 689382544-689382565 LPC: Data: DATA: 0x2c
   # 222346,6310537896.00000000000000000000,DATA: 0x2c
   
   
   if ',' in TPM_DATA_FIFO_0_transactions[int(match.start()/2)]:
       type='dsview'
       vmk_header_start_time = int(re.split('[,\.]',TPM_DATA_FIFO_0_transactions[int(match.start()/2)])[1])/1000000000.0
       if samplerate!=0:
           print("[+] BitLocker VMK header starts at sample: ", vmk_header_start_time*samplerate)
       print("[+] BitLocker VMK header starts after:    ", vmk_header_start_time, " seconds")
   else:
       type='pulseview'
       vmk_header_start_sample = TPM_DATA_FIFO_0_transactions[int(match.start()/2)].split('-')[0]
       print("[+] BitLocker VMK header starts at sample: ", vmk_header_start_sample)
       if samplerate!=0:
           print("[+] BitLocker VMK header starts after:    ", int(vmk_header_start_sample)/samplerate, " seconds")
       else:
           print("    (divide by samplerate to get time)")
   print()
   
   print("[+] Found BitLocker VMK header: ", match.group(1))
   print("[+] Found BitLocker VMK:        ", match.group(2))
   print()

if __name__ == '__main__':
   main()

