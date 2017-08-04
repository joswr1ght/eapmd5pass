/* Copyright (c) 2007, Joshua Wright <jwright@hasborg.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>		/* for ntohs() */
#include <errno.h>
#include <sys/types.h>
#include "utils.h"

void lamont_hdump(unsigned char *bp, unsigned int length);
char *printmac(unsigned char *mac);

/* A better version of hdump, from Lamont Granquist.  Modified slightly
   by Fyodor (fyodor@DHP.com) */
void lamont_hdump(unsigned char *bp, unsigned int length)
{

	/* stolen from tcpdump, then kludged extensively */

	static const char asciify[] =
	    "................................ !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~.................................................................................................................................";

	const unsigned short *sp;
	const unsigned char *ap;
	unsigned int i, j;
	int nshorts, nshorts2;
	int padding;

	printf("\n\t");
	padding = 0;
	sp = (unsigned short *)bp;
	ap = (unsigned char *)bp;
	nshorts = (unsigned int)length / sizeof(unsigned short);
	nshorts2 = (unsigned int)length / sizeof(unsigned short);
	i = 0;
	j = 0;
	while (1) {
		while (--nshorts >= 0) {
			printf(" %04x", ntohs(*sp));
			sp++;
			if ((++i % 8) == 0)
				break;
		}
		if (nshorts < 0) {
			if ((length & 1) && (((i - 1) % 8) != 0)) {
				printf(" %02x  ", *(unsigned char *)sp);
				padding++;
			}
			nshorts = (8 - (nshorts2 - nshorts));
			while (--nshorts >= 0) {
				printf("     ");
			}
			if (!padding)
				printf("     ");
		}
		printf("  ");

		while (--nshorts2 >= 0) {
			printf("%c%c", asciify[*ap], asciify[*(ap + 1)]);
			ap += 2;
			if ((++j % 8) == 0) {
				printf("\n\t");
				break;
			}
		}
		if (nshorts2 < 0) {
			if ((length & 1) && (((j - 1) % 8) != 0)) {
				printf("%c", asciify[*ap]);
			}
			break;
		}
	}
	if ((length & 1) && (((i - 1) % 8) == 0)) {
		printf(" %02x", *(unsigned char *)sp);
		printf("                                       %c",
		       asciify[*ap]);
	}
	printf("\n");
}

int str2mac(char *string, uint8_t *mac)
{

	char *ptr, *next;
	unsigned long val;
	int i;

	to_upper(string);

	ptr = next = string;
	for (i = 0; i < 6; i++) {
		if ((val = strtoul(next, &ptr, 16)) > 255) {
			return (-1);
		}
		mac[i] = (uint8_t) val;
		if ((next == ptr) && (i != 6 - 1)) {
			return (-1);
		}
		next = ptr + 1;
	}

	return (0);
}

void to_upper (char *s)
{

	char *p;
	char offset;

	offset = 'A' - 'a';
	for (p = s; *p != '\0'; p++) {
		if (islower(*p)) {
			*p += offset;
		}
	}
}


int str2hex (char *string, uint8_t *hexstr, int len)
{
	char *ptr, *next;
	unsigned long val;
	int i;

	ptr = next = string;
	for(i=0;i < len;i++) {
		if((val = strtoul(next, &ptr, 16)) > 255) {
			errno = EINVAL;
			return(-1);
		}
		hexstr[i] = (unsigned int)val;
		if((next == ptr) && (i != len - 1)) {
			errno = EINVAL;
			return(-1);
		}
		next = ptr + 1;
	}

	return(1);
}
