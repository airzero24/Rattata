# Rattata
Rattata is a python 2.7 based C2 framework designed to be similiar to Metasploit's Meterpreter in functionality (albeit not nearly as functional). Rattata consists of a server and implant (client) component. There are two pre-built implants, one for Windows systems and one for Unix systems. The idea is to either use these implants as is or compile to stand-alone excutable files with either PyInstaller or Py2exe (both have been tested). 

This was also my first actual programming project, so I'm sure it's riddled with bugs. Let me know if you have ways to improve it!

## Installation

`pip install -r requirements.txt`

The windows based implant also requires Pywin32 for the Windows API componets of the implant.

## Usage

You will need to edit the lhost and lport variables in the implant files to point to your C2 server. It's also recommended to change the CIPHER key in both the server and the implant. The nix implant does not contain the same functionality as the windows implant

`python server.py <C2 server address> <listening port>`

Next, edit the implant-<OS>.py file to point the lhost and lport variabels to your C2 server. 

`python implant-win.py or implant-nix.py`

## Session Management

Rattata allows for multiple connections to the server and subsequent session management. To be able to interact with new sessions, the command `checkconns` will need to be issued from the main menu, see example below. *Note: The session management doesn't work apparently, while the server can handle multiple connections you can only interact with one thread at a time, working on this.

```
[*] Waiting for connection...

[+] Connection recieved from 127.0.0.1:44996

rattata>list
[*] Available implant connections

[*] Format: <session_id> <ipaddress:port>

 1 127.0.0.1:44996 (Established)


rattata>interact 1
127.0.0.1:rattata>whoami
[+] Sent command 'whoami' to implant!
[+] Result from implant:
dev

127.0.0.1:rattata>back
rattata>checkconns
[+] Connection recieved from 127.0.0.1:45002

rattata>list
[*] Available implant connections

[*] Format: <session_id> <ipaddress:port>

 1 127.0.0.1:44996 (Established)


 2 127.0.0.1:45002 (Established)


rattata>interact 2
127.0.0.1:rattata>whoami
[+] Sent command 'whoami' to implant!
[+] Result from implant:
dev

127.0.0.1:rattata>back
rattata>list
[*] Available implant connections

[*] Format: <session_id> <ipaddress:port>

 1 127.0.0.1:44996 (Established)


 2 127.0.0.1:45002 (Established)


rattata>quit
[*] Exiting Rattata...
```

## TODO

#### Add Upload/Download functionality

## Big Thanks
I really want to thank @HackingDave from [TrustSec](https://www.trustedsec.com/) for all his great work and amazing contributions to the community. A lot of the code in Rattata is based off of his [TrevorC2](https://github.com/trustedsec/trevorc2) project. 

Also want to thank the guys at [Black Hills Info Sec](https://www.blackhillsinfosec.com/) for their amazing work and [vsagent](https://github.com/rev10d/504vsa) which was the original idea that got me working on this project.
