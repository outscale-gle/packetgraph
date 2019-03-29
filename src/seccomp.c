/* Copyright 2019 Outscale SAS
 *
 * This file is part of Packetgraph.
 *
 * Packetgraph is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as published
 * by the Free Software Foundation.
 *
 * Packetgraph is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Packetgraph.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <packetgraph/common.h>
#include <packetgraph/seccomp-bpf.h>


#include "syscall-names.h"

const char * const msg_needed = "Looks like you also need syscall: ";

/* Since "sprintf" is technically not signal-safe, reimplement %d here. */
static void write_uint(char *buf, unsigned int val)
{
	int width = 0;
	unsigned int tens;

	if (val == 0) {
		strcpy(buf, "0");
		return;
	}
	for (tens = val; tens; tens /= 10)
		++ width;
	buf[width] = '\0';
	for (tens = val; tens; tens /= 10)
		buf[--width] = '0' + (tens % 10);
}

static void syscall_reporter(int nr, siginfo_t *info, void *void_context)
{
	char buf[128];
	ucontext_t *ctx = (ucontext_t *)(void_context);
	unsigned int syscall;

	if (!ctx)
		return;
	syscall = ctx->uc_mcontext.gregs[REG_SYSCALL];
	strcpy(buf, msg_needed);
	if (syscall < sizeof(syscall_names)) {
		strcat(buf, syscall_names[syscall]);
		strcat(buf, "(");
	}
	write_uint(buf + strlen(buf), syscall);
	if (syscall < sizeof(syscall_names))
		strcat(buf, ")");
	strcat(buf, "\n");
	write(STDOUT_FILENO, buf, strlen(buf));
	_exit(1);
}

int pg_init_syscall_reporter(void)
{
	struct sigaction act;
	sigset_t mask;

	memset(&act, 0, sizeof(act));
	sigemptyset(&mask);
	sigaddset(&mask, SIGSYS);

	act.sa_sigaction = &syscall_reporter;
	act.sa_flags = SA_SIGINFO;
	if (sigaction(SIGSYS, &act, NULL) < 0) {
		perror("sigaction");
		return -1;
	}
	if (sigprocmask(SIG_UNBLOCK, &mask, NULL)) {
		perror("sigprocmask");
		return -1;
	}
	return 0;
}

int pg_init_syscall_catcher(void)
{
	struct sock_filter filter[] = {
		VALIDATE_ARCHITECTURE,
		EXAMINE_SYSCALL,

		/* List allowed syscalls */
		ALLOW_SYSCALL(exit_group),
		ALLOW_SYSCALL(exit),
		ALLOW_SYSCALL(read),
		ALLOW_SYSCALL(write),
		ALLOW_SYSCALL(open),
		ALLOW_SYSCALL(close),
		ALLOW_SYSCALL(fstat),
		ALLOW_SYSCALL(lstat),
		ALLOW_SYSCALL(lseek),
		ALLOW_SYSCALL(poll),
		ALLOW_SYSCALL(mmap),
		ALLOW_SYSCALL(mprotect),
		ALLOW_SYSCALL(munmap),
		ALLOW_SYSCALL(brk),
		ALLOW_SYSCALL(rt_sigaction),
		ALLOW_SYSCALL(rt_sigprocmask),
		ALLOW_SYSCALL(ioctl),
		ALLOW_SYSCALL(access),
		ALLOW_SYSCALL(pipe),
		ALLOW_SYSCALL(pipe2),
		ALLOW_SYSCALL(sched_yield),
		ALLOW_SYSCALL(dup2),
		ALLOW_SYSCALL(nanosleep),
		ALLOW_SYSCALL(socket),
		ALLOW_SYSCALL(sendto),
		ALLOW_SYSCALL(recvmsg),
		ALLOW_SYSCALL(bind),
		ALLOW_SYSCALL(listen),
		ALLOW_SYSCALL(getsockname),
		ALLOW_SYSCALL(clone),
		ALLOW_SYSCALL(execve),
		ALLOW_SYSCALL(wait4),
		ALLOW_SYSCALL(kill),
		ALLOW_SYSCALL(fcntl),
		ALLOW_SYSCALL(fsync),
		ALLOW_SYSCALL(getdents),
		ALLOW_SYSCALL(rename),
		ALLOW_SYSCALL(unlink),
		ALLOW_SYSCALL(fstatfs),
		ALLOW_SYSCALL(gettid),
		ALLOW_SYSCALL(futex),
		ALLOW_SYSCALL(sched_setaffinity),
		ALLOW_SYSCALL(tgkill),
		ALLOW_SYSCALL(set_robust_list),
		ALLOW_SYSCALL(fallocate),

		/* System */
		ALLOW_SYSCALL(fork),
		ALLOW_SYSCALL(waitid),
		ALLOW_SYSCALL(signalfd),
		ALLOW_SYSCALL(signalfd4),
		ALLOW_SYSCALL(setpgid),
		ALLOW_SYSCALL(mlock),
		ALLOW_SYSCALL(mlockall),
		ALLOW_SYSCALL(getrusage),
		ALLOW_SYSCALL(times),
		ALLOW_SYSCALL(rt_sigpending),
		ALLOW_SYSCALL(semop),
		ALLOW_SYSCALL(flock),
		ALLOW_SYSCALL(setitimer),
		ALLOW_SYSCALL(alarm),
		ALLOW_SYSCALL(timer_create),
		ALLOW_SYSCALL(io_setup),
		ALLOW_SYSCALL(ioperm),
		ALLOW_SYSCALL(madvise),
		ALLOW_SYSCALL(mq_open),

		/* Vhost */
		ALLOW_SYSCALL(set_tid_address),
		ALLOW_SYSCALL(rt_sigreturn),
		ALLOW_SYSCALL(getppid),
		ALLOW_SYSCALL(statfs),
		ALLOW_SYSCALL(getuid),
		ALLOW_SYSCALL(getcwd),
		ALLOW_SYSCALL(getgid),
		ALLOW_SYSCALL(stat),
		ALLOW_SYSCALL(arch_prctl),
		ALLOW_SYSCALL(geteuid),
		ALLOW_SYSCALL(getegid),
		ALLOW_SYSCALL(getpid),
		ALLOW_SYSCALL(getrlimit),
		ALLOW_SYSCALL(unlinkat),
		ALLOW_SYSCALL(newfstatat),
		ALLOW_SYSCALL(sched_getaffinity),
		ALLOW_SYSCALL(pwritev),
		ALLOW_SYSCALL(get_mempolicy),
		ALLOW_SYSCALL(setresuid),
		ALLOW_SYSCALL(pread64),
		ALLOW_SYSCALL(select),
		ALLOW_SYSCALL(ftruncate),
		ALLOW_SYSCALL(mbind),
		ALLOW_SYSCALL(set_thread_area),
		ALLOW_SYSCALL(setresgid),
		ALLOW_SYSCALL(rt_sigtimedwait),
		ALLOW_SYSCALL(dup),
		ALLOW_SYSCALL(shutdown),
		ALLOW_SYSCALL(epoll_create1),
		ALLOW_SYSCALL(preadv),
		ALLOW_SYSCALL(accept),
		ALLOW_SYSCALL(pwrite64),
		ALLOW_SYSCALL(readlink),
		ALLOW_SYSCALL(umask),
		ALLOW_SYSCALL(clock_gettime),
		ALLOW_SYSCALL(ppoll),
		ALLOW_SYSCALL(recvfrom),
		ALLOW_SYSCALL(eventfd2),

		/* Tap */
		ALLOW_SYSCALL(fdatasync),
		ALLOW_SYSCALL(mq_getsetattr),
		ALLOW_SYSCALL(connect),
		ALLOW_SYSCALL(epoll_pwait),
		ALLOW_SYSCALL(mkdir),
		ALLOW_SYSCALL(sysinfo),
		ALLOW_SYSCALL(prctl),
		ALLOW_SYSCALL(mount),
		ALLOW_SYSCALL(capset),
		ALLOW_SYSCALL(unshare),
		ALLOW_SYSCALL(setuid),
		ALLOW_SYSCALL(sendmsg),
		ALLOW_SYSCALL(umount2),
		ALLOW_SYSCALL(getsockopt),
		ALLOW_SYSCALL(getpeername),
		ALLOW_SYSCALL(uname),
		ALLOW_SYSCALL(getpgrp),
		ALLOW_SYSCALL(setns),
		ALLOW_SYSCALL(setsockopt),
		ALLOW_SYSCALL(capget),
		ALLOW_SYSCALL(add_key),
		ALLOW_SYSCALL(openat),

		KILL_PROCESS,
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(*filter)),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		return -1;
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
		return -1;
	return 0;
}
