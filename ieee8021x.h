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

#ifndef IEEE8021X_H
#define IEEE8021X_H

/* The 802.1X header indicates a version, type and length */
struct ieee8021x {
	uint8_t    version;
	uint8_t    type;
	uint16_t   len;
} __attribute__ ((packed));
#define DOT1XHDR_LEN sizeof(struct ieee8021x)

#define DOT1X_VERSION1 1 
#define DOT1X_VERSION2 2 
#define DOT1X_TYPE_EAP 0

#endif
