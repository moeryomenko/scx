// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Maxim Eryomenko <maxim_eryomenko@rambler.ru>
//
// infinity_workload.c - small workload helper for the scx_infinity
// harnesses.
//
// Modes:
//
//   burn SECONDS             busy loop
//   sleeper SECONDS          one-millisecond sleep loop
//   forkexec SECONDS         fork and exec /bin/true in a loop
//   yield SECONDS            sched_yield loop
//   migrate SECONDS          alternate the affinity between two CPUs
//   probe SECONDS MASK [broaden]
//                            sample the running CPU and count samples
//                            outside MASK, then print one key=value line
//
// MASK is all or a cpulist such as 0-3,8. With broaden the process first
// records its current CPU, sets the full CPU set, sleeps for one
// millisecond and then samples. The scheduler sees a wakeup whose
// previous CPU is the original CPU. The placement check uses this to
// observe select_cpu.
//
// The helper is deliberately free of dependencies beyond libc. It prints
// key=value pairs on stdout. The harness escapes the values into JSON.

#define _GNU_SOURCE

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CPU_LIMIT 1024

static long long now_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static void sleep_ms(long milliseconds)
{
	struct timespec ts = {
		.tv_sec	 = milliseconds / 1000,
		.tv_nsec = (milliseconds % 1000) * 1000000LL,
	};

	while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
		;
}

static int set_all_cpus(cpu_set_t *set)
{
	int cpu;

	CPU_ZERO(set);
	for (cpu = 0; cpu < CPU_LIMIT; cpu++)
		CPU_SET(cpu, set);
	return sched_setaffinity(0, sizeof(*set), set);
}

// Parse one cpulist. Return 0 on success.
static int parse_cpulist(const char *text, cpu_set_t *set)
{
	char *copy;
	char *save = NULL;
	char *part;
	int   rc = 0;

	CPU_ZERO(set);
	copy = strdup(text);
	if (copy == NULL)
		return -1;
	for (part = strtok_r(copy, ",", &save); part != NULL;
	     part = strtok_r(NULL, ",", &save)) {
		char *dash = strchr(part, '-');
		long  first;
		long  last;
		long  cpu;

		if (dash != NULL) {
			*dash = '\0';
			first = strtol(part, NULL, 10);
			last  = strtol(dash + 1, NULL, 10);
		} else {
			first = strtol(part, NULL, 10);
			last  = first;
		}
		if (first < 0 || last < first || last >= CPU_LIMIT) {
			rc = -1;
			break;
		}
		for (cpu = first; cpu <= last; cpu++)
			CPU_SET((int)cpu, set);
	}
	free(copy);
	return rc;
}

static int parse_mask(const char *text, cpu_set_t *set)
{
	if (strcmp(text, "all") == 0)
		return set_all_cpus(set);
	return parse_cpulist(text, set);
}

static int cmd_burn(double seconds)
{
	volatile unsigned long long count = 0;
	long long end = now_ms() + (long long)(seconds * 1000.0);

	while (now_ms() < end)
		count++;
	/* Keep the compiler from removing the loop. */
	if (count == 0)
		return 1;
	return 0;
}

static int cmd_sleeper(double seconds)
{
	long long end = now_ms() + (long long)(seconds * 1000.0);

	while (now_ms() < end)
		sleep_ms(1);
	return 0;
}

static int cmd_forkexec(double seconds)
{
	long long end = now_ms() + (long long)(seconds * 1000.0);

	while (now_ms() < end) {
		pid_t pid = fork();

		if (pid == 0) {
			execl("/bin/true", "true", (char *)NULL);
			_exit(127);
		}
		if (pid > 0) {
			int status;

			while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
				;
		}
	}
	return 0;
}

static int cmd_yield(double seconds)
{
	unsigned long long calls = 0;
	long long	   end	 = now_ms() + (long long)(seconds * 1000.0);

	while (now_ms() < end) {
		sched_yield();
		calls++;
	}
	printf("yields=%llu\n", calls);
	return 0;
}

static int cmd_migrate(double seconds)
{
	cpu_set_t	   allowed;
	cpu_set_t	   target;
	int		   cpus[CPU_LIMIT];
	int		   nr = 0;
	int		   cpu;
	unsigned long long migrations = 0;
	long long	   end;

	if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0)
		return 1;
	for (cpu = 0; cpu < CPU_LIMIT; cpu++) {
		if (CPU_ISSET(cpu, &allowed))
			cpus[nr++] = cpu;
	}
	if (nr < 2)
		return 1;
	end = now_ms() + (long long)(seconds * 1000.0);
	while (now_ms() < end) {
		CPU_ZERO(&target);
		CPU_SET(cpus[0], &target);
		if (sched_setaffinity(0, sizeof(target), &target) == 0)
			migrations++;
		sleep_ms(1);
		CPU_ZERO(&target);
		CPU_SET(cpus[nr - 1], &target);
		if (sched_setaffinity(0, sizeof(target), &target) == 0)
			migrations++;
		sleep_ms(1);
	}
	printf("migrations=%llu\n", migrations);
	return 0;
}

static int cmd_probe(double seconds, const char *mask, bool broaden)
{
	cpu_set_t check;
	cpu_set_t target;
	bool	  seen[CPU_LIMIT] = { false };
	char	  distinct[4096];
	size_t	  used	      = 0;
	long long samples     = 0;
	long long out_of_mask = 0;
	long long end;
	int	  first_cpu = sched_getcpu();
	int	  min_cpu   = -1;
	int	  max_cpu   = -1;
	int	  cpu;

	if (parse_mask(mask, &check) != 0) {
		fprintf(stderr, "bad mask: %s\n", mask);
		return 2;
	}
	if (broaden) {
		if (set_all_cpus(&target) != 0)
			return 1;
		sleep_ms(1);
	} else if (sched_setaffinity(0, sizeof(check), &check) != 0) {
		return 1;
	}

	end = now_ms() + (long long)(seconds * 1000.0);
	while (now_ms() < end) {
		cpu = sched_getcpu();
		if (cpu < 0)
			cpu = -1;
		samples++;
		if (cpu < 0 || !CPU_ISSET(cpu, &check))
			out_of_mask++;
		if (cpu >= 0 && cpu < CPU_LIMIT) {
			if (!seen[cpu]) {
				int written = snprintf(distinct + used,
						       sizeof(distinct) - used,
						       used == 0 ? "%d" : ",%d",
						       cpu);

				if (written > 0 &&
				    (size_t)written < sizeof(distinct) - used)
					used += (size_t)written;
				seen[cpu] = true;
			}
			if (min_cpu < 0 || cpu < min_cpu)
				min_cpu = cpu;
			if (cpu > max_cpu)
				max_cpu = cpu;
		}
		sleep_ms(1);
	}
	printf("samples=%lld out_of_mask=%lld first_cpu=%d min_cpu=%d max_cpu=%d distinct=%s\n",
	       samples, out_of_mask, first_cpu, min_cpu, max_cpu,
	       used == 0 ? "none" : distinct);
	return 0;
}

static void usage(const char *name)
{
	fprintf(stderr,
		"usage: %s burn|sleeper|forkexec|yield|migrate SECONDS\n"
		"       %s probe SECONDS all|CPULIST [broaden]\n",
		name, name);
}

int main(int argc, char **argv)
{
	double seconds;

	if (argc < 3) {
		usage(argv[0]);
		return 2;
	}
	seconds = strtod(argv[2], NULL);
	if (seconds <= 0) {
		usage(argv[0]);
		return 2;
	}
	if (strcmp(argv[1], "burn") == 0)
		return cmd_burn(seconds);
	if (strcmp(argv[1], "sleeper") == 0)
		return cmd_sleeper(seconds);
	if (strcmp(argv[1], "forkexec") == 0)
		return cmd_forkexec(seconds);
	if (strcmp(argv[1], "yield") == 0)
		return cmd_yield(seconds);
	if (strcmp(argv[1], "migrate") == 0)
		return cmd_migrate(seconds);
	if (strcmp(argv[1], "probe") == 0) {
		bool	    broaden = false;
		const char *mask    = "all";

		if (argc >= 4)
			mask = argv[3];
		if (argc >= 5 && strcmp(argv[4], "broaden") == 0)
			broaden = true;
		return cmd_probe(seconds, mask, broaden);
	}
	usage(argv[0]);
	return 2;
}
