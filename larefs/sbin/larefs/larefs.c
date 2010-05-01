/*
   File name: larefs_ctl.c
   Date:      28.04.2010 02:26
   Author:    Lukas Czerner <czerner.lukas@gmail.com>
   Project:   

   Copyright (C) 2002 Lukas Czerner <czerner.lukas@gmail.com>

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   in a file called COPYING along with this program; if not, write to
   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA
   02139, USA.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fs/larefs/larefs.h>

#define MAX_COMMAND_NAME	10
#define MAX_ARG_NAME		20

/*
struct lrfs_attach_info {
	char *name;
	int priority;
};
*/
enum command_list {
	ATTACH,
	DETACH,
	TOGGLE,
	PRIOR,
	COMM_COUNT
};

struct commands {
	enum command_list command;
	char string[MAX_COMMAND_NAME];
	char params[MAX_ARG_NAME];
};

struct commands comm[] = {
	{ATTACH, "attach", "Priority [int]"},
	{DETACH, "detach", "Priority [int]"},
	{TOGGLE, "toggle", ""},
	{PRIOR, "priority", "Priority [int]"}
};

struct arguments {
	int command;
	int param;
	char *fltname;
	char *directory;
};

int __strncmp(char *, char *, int);
int get_command(char *);
void print_help(char *);
int get_arguments(int , char **, struct arguments *);


void print_help(char *func) {
	fprintf(stderr, "usage: %s [command] <filter> <directory>\n", func);
	fprintf(stderr, "Supported commands are:\n");
	for (int i = 0; i < COMM_COUNT; i++) {
		fprintf(stderr,"\t%s <%s>\n",comm[i].string, comm[i].params);
	}
	return;
}

int __strncmp(char *s1, char *s2, int len) {
	int i;
	for (i = 0; i < len; i++) {
		if ((s1[i] != '\0') && (s1[i] == s2[i]))
			continue;
		break;
	}

	return i;
}

int
get_command(char *string) {
	int len = 0, max[2] = {0, COMM_COUNT}; /* 0 - similarity, 1 - command */

	for (int i = 0; i < COMM_COUNT; i++) {
		len = __strncmp(comm[i].string, string, MAX_COMMAND_NAME);

		if (len == 0)
			continue;

		if (comm[i].string[len] == string[len])
			return i;

		if (len == max[0])
			return COMM_COUNT;

		if ((len > max[0]) && (string[len] == '\0')) {
			max[0] = len;
			max[1] = i;
		}
	}
	return max[1];
}

int
get_arguments(int argc, char **argv, struct arguments *args) {
	struct arguments am;

	am = *args;

	am.command = get_command(argv[1]);

	switch (am.command) {
		case TOGGLE:
		case DETACH:
			if (argc != 4) {
				return (1);
			}
			am.fltname = argv[2];
			am.directory = argv[3];
			break;
		case ATTACH:
		case PRIOR:
			if (argc != 5) {
				return (1);
			}
			am.fltname = argv[2];
			am.param = atoi(argv[3]);
			am.directory = argv[4];
			break;
		default:
			return (1);
	}

	*args = am;
	return (0);
}

int main(int argc, char **argv)
{
	int fd, err;
	struct larefs_attach_info ainfo;
	struct arguments args;

	err = get_arguments(argc, argv, &args);
	if (err) {
		print_help(argv[0]);
		return 1;
	}

	fd = open(args.directory, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	switch (args.command) {

	case ATTACH:
		strncpy(ainfo.name, args.fltname, MAXFILTERNAME);
		ainfo.priority = args.param;

		fprintf(stdout,"Attach filter %s, prio: %d\n",ainfo.name, ainfo.priority);

		if (ioctl(fd, LRFS_ATTACH, &ainfo)) {
			if (errno == EOPNOTSUPP)
				fprintf(stderr, "LRFS_ATTACH not supported\n");
			else
				perror("LRFS_ATTACH");
			return 1;
		}

		break;

	case DETACH:
		strncpy(ainfo.name, args.fltname, MAXFILTERNAME);

		if (ioctl(fd, LRFS_DETACH, &ainfo.name)) {
			if (errno == EOPNOTSUPP)
				fprintf(stderr, "LRFS_DETACH not supported\n");
			else
				perror("LRFS_DETACH");
			return 1;
		}
		break;

	case TOGGLE:
		strncpy(ainfo.name, args.fltname, MAXFILTERNAME);

		if (ioctl(fd, LRFS_TGLACT, &ainfo.name)) {
			if (errno == EOPNOTSUPP)
				fprintf(stderr, "LRFS_TOGGLE not supported\n");
			else
				perror("LRFS_TOGGLE");
			return 1;
		}
		break;

	case PRIOR:
		strncpy(ainfo.name, args.fltname, MAXFILTERNAME);
		ainfo.priority = args.param;

		if (ioctl(fd, LRFS_CHPRIO, &ainfo)) {
			if (errno == EOPNOTSUPP)
				fprintf(stderr, "LRFS_CHPRIO not supported\n");
			else
				perror("LRFS_CHPRIO");
			return 1;
		}

		break;

	default:
		print_help(argv[0]);
		return 1;
	}
	
	return 0;
}

/* end of larefs_ctl.c */
