// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/pmap.h>
#include <kern/kclock.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display information about our stack", mon_backtrace },
	{ "showmapping", "display the physical page mappings and corresponding permission bits", mon_showmapping },
	{ "set", "change a virtual address flags:\n{P,W,U} => {Present,Writeable,User} : {0,1,2} => {clear,set,change}", mon_set },
	{ "dump", "{P,V} for addresses => range {start,end}", mon_dump },

};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	uint32_t * ebp = ( uint32_t* ) read_ebp();
	cprintf("Stack backtrace:\n");
	while( ebp != NULL){
		cprintf("ebp %x eip %x args",(ebp),*(ebp+1));

		int i = 2;
		for( ; i < 7; i++){
			cprintf(" %08x",*(ebp+i));
		}
		cprintf("\n");

		struct Eipdebuginfo info;
		int val = debuginfo_eip(*(ebp+1) , &info);
		// ex : kern/monitor.c:143: monitor+106
		cprintf("\t%s:%d: %.*s+%d\n",info.eip_file,info.eip_line,info.eip_fn_namelen, info.eip_fn_name,
      *(ebp+1) - info.eip_fn_addr  );

		ebp = ( uint32_t * ) * ebp;
	}
	return 0;
}	

int
mon_showmapping(int argc, char **argv, struct Trapframe *tf)
{
	if ( argc != 3) panic("your command should be like showmappings Address1 Address2");
	uint32_t begin,end;
	begin = mon_xtoi(argv[1]);
	end  = mon_xtoi(argv[2]);
	//cprintf("%d %d\n",begin,end);
	pte_t * pte;
	for(; begin <= end ; begin += PGSIZE){
		pte = pgdir_walk(kern_pgdir,(void * )begin, 1);
		if( pte == NULL){
			cprintf("memory exception\n");
			return 0;
		}
		cprintf("virtual address: %x\n",begin);
		cprintf("physical address: %x\n",PTE_ADDR(pte) | PGOFF(begin) );
		cprintf("PTE_P : %x PTE_U: %x PTE_W: %x\n",( (*pte) & PTE_P ),( (*pte) & PTE_U ) >> (2), ((*pte) & PTE_W)>> (1) );
	}
	return 0;
}	

int
mon_set(int argc, char **argv, struct Trapframe *tf)
{
	if ( argc != 4) panic("invalid arguments");
	int va = mon_xtoi(argv[1]);
	int perm;
	if ( *argv[2] == 'P' || *argv[2] == 'p'){
		perm = PTE_P;
	} else if(*argv[2] == 'W' || *argv[2] == 'w' ){
		perm = PTE_W;
	} else if(*argv[2] == 'U' || *argv[2] == 'u' ){
		perm = PTE_U;
	}else{
		cprintf("error in comand - back to command window");
		return 0;
	}
	pte_t * pte = pgdir_walk(kern_pgdir,(void *) va,1);
	if ( pte == NULL){
		cprintf("memory exception");
		return 0;
	}
	cprintf("orignal: virtual address: %x ",va);
	cprintf("PTE_P : %x PTE_U: %x PTE_W: %x\n",( (*pte) & PTE_P ),( (*pte) & PTE_U ) >> (2), ((*pte) & PTE_W)>> (1) );
	
	if( *argv[3] == '0' ){
		*pte = *pte & ( ~ perm);
	} else if ( *argv[3] == '1'){
		*pte = *pte | ( perm );
	} else if ( *argv[3] == '2'){
		*pte = *pte ^ ( perm );
	}else{
		cprintf("error in command - back to command window");
		return 0;
	}
	cprintf("edited: virtual address: %x ",va);
	cprintf("PTE_P : %x PTE_U: %x PTE_W: %x\n",( (*pte) & PTE_P ),( (*pte) & PTE_U ) >> (2), ((*pte) & PTE_W)>> (1) );
	
	return 0;
}	
// showmapping 0xf0000000 0xffffffff
int
mon_dump(int argc, char **argv, struct Trapframe *tf)
{
	if ( argc != 4 ) panic("invalid arguments");
	int start,end;
	start = mon_xtoi(argv[2]);
	end = mon_xtoi(argv[3]);
	pte_t * pte;
	uint32_t * ph;
	for( ; start <= end ; start ++){
		if ( *argv[1] == 'V' || *argv[1] == 'v')
			{
				pte = pgdir_walk(kern_pgdir,(void*)start,1);
				ph =(uint32_t *)  ( PTE_ADDR(pte) | PGOFF(start) );
			}
			else ph=(uint32_t *) start;
			cprintf("(before) address = %x value = %x\n",ph,*ph);
			*ph=0;
			cprintf("(after) address = %x value = %x\n",ph,*ph);
	}

//dump v 0xf0000005 0xf0000009
	return 0;
}
/***** helper functions *****/
uint32_t mon_xtoi(char * arg){
	uint32_t rst=0;
	uint32_t mul = 1;
	uint32_t add = 0;
	uint32_t sz = strlen(arg);
	if (arg[0] != '0' && ( arg[1] != 'x' || arg[1] != 'X' ) ) panic("invalid HEX");
	//cprintf("%d\n",sz);
	sz = sz - 1;
	for(; sz >= 2 ; sz--){
		if ( arg[sz] >= 'a' && arg[sz] <= 'z'){
			add = (arg[sz] -'a' + 10);
		}
		else if ( arg[sz] >= 'A' && arg[sz] <= 'Z'){
			add = (arg[sz] -'a' + 10);
		}
		else{
			add = arg[sz] - '0';
		}
		add *= mul;
		mul *= 16;
		rst += add;
	}
	return rst;
}

/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");
	// cprintf("%m%s\n%m%s\n%m%s\n", 
 //    0x0100, "blue", 0x0200, "green", 0x0400, "red");

	// cprintf("x=%d y=%d\n", 3);

	while (1) {
		buf = readline("AbtalELDigital> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
