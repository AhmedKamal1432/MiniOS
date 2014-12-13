// Simple implementation of cprintf console output for the kernel,
// based on printfmt() and the kernel console's cputchar().

#include <inc/types.h>
#include <inc/stdio.h>
#include <inc/stdarg.h>


static void
putch(int ch, int *cnt)
{
	cputchar(ch);
	*cnt++;
}

int
vcprintf(const char *fmt, va_list ap)
{
	int cnt = 0;

	vprintfmt((void*)putch, &cnt, fmt, ap); // send numofper
	return cnt;
}

int
cprintf(const char *fmt, ...)
{
	va_list ap;
	int cnt;
	// loop over fmt, count all % -- 
	va_start(ap, fmt);
	cnt = vcprintf(fmt, ap); // send numofper
	va_end(ap);

	return cnt;
}

