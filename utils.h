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

/* Prototypes */
void lamont_hdump(unsigned char *bp, unsigned int length);
int str2mac(char *string, uint8_t *mac);
void to_upper (char *s);
int str2hex (char *string, uint8_t *hexstr, int len);
