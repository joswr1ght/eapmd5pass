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

#ifndef IEEE80211_H
#define IEEE80211_H

#define DOT11HDR_A1_LEN 10
#define DOT11HDR_A3_LEN 24
#define DOT11HDR_A4_LEN 30
#define DOT11HDR_MAC_LEN 6
#define DOT11HDR_MINLEN DOT11HDR_A1_LEN

#define DOT11_FC_TYPE_MGMT 0
#define DOT11_FC_TYPE_CTRL 1
#define DOT11_FC_TYPE_DATA 2

#define DOT11_FC_SUBTYPE_ASSOCREQ    0
#define DOT11_FC_SUBTYPE_ASSOCRESP   1
#define DOT11_FC_SUBTYPE_REASSOCREQ  2
#define DOT11_FC_SUBTYPE_REASSOCRESP 3
#define DOT11_FC_SUBTYPE_PROBEREQ    4
#define DOT11_FC_SUBTYPE_PROBERESP   5
#define DOT11_FC_SUBTYPE_BEACON      8
#define DOT11_FC_SUBTYPE_ATIM        9
#define DOT11_FC_SUBTYPE_DISASSOC    10
#define DOT11_FC_SUBTYPE_AUTH        11
#define DOT11_FC_SUBTYPE_DEAUTH      12

#define DOT11_FC_SUBTYPE_PSPOLL      10
#define DOT11_FC_SUBTYPE_RTS         11
#define DOT11_FC_SUBTYPE_CTS         12
#define DOT11_FC_SUBTYPE_ACK         13
#define DOT11_FC_SUBTYPE_CFEND       14
#define DOT11_FC_SUBTYPE_CFENDACK    15

#define DOT11_FC_SUBTYPE_DATA            0
#define DOT11_FC_SUBTYPE_DATACFACK       1
#define DOT11_FC_SUBTYPE_DATACFPOLL      2
#define DOT11_FC_SUBTYPE_DATACFACKPOLL   3
#define DOT11_FC_SUBTYPE_DATANULL        4
#define DOT11_FC_SUBTYPE_CFACK           5
#define DOT11_FC_SUBTYPE_CFACKPOLL       6
#define DOT11_FC_SUBTYPE_CFACKPOLLNODATA 7
#define DOT11_FC_SUBTYPE_QOSDATA         8
/* 9 - 11 reserved as of 11/7/2005 - JWRIGHT */
#define DOT11_FC_SUBTYPE_QOSNULL         12

struct dot11hdr {
	union {
		struct {
			uint8_t		version:2;
			uint8_t		type:2;
			uint8_t		subtype:4;
			uint8_t		to_ds:1;
			uint8_t		from_ds:1;
			uint8_t		more_frag:1;
			uint8_t		retry:1;
			uint8_t		pwrmgmt:1;
			uint8_t		more_data:1;
			uint8_t		protected:1;
			uint8_t		order:1;
		} __attribute__ ((packed)) fc;

		uint16_t	fchdr;
	} u1;

	uint16_t	duration;
	uint8_t		addr1[6];
	uint8_t		addr2[6];
	uint8_t		addr3[6];

	union {
		struct {
			uint16_t	fragment:4;
			uint16_t	sequence:12;
		} __attribute__ ((packed)) seq;

		uint16_t	seqhdr;
	} u2;

} __attribute__ ((packed));

#define dot11hdra3 dot11hdr
#define ieee80211 dot11hdr

struct ieee80211_qos {
	uint8_t priority:3;
	uint8_t reserved3:1;
	uint8_t eosp:1;
	uint8_t ackpol:2;
	uint8_t reserved1:1;
	uint8_t reserved2;
} __attribute__ ((packed));
#define DOT11HDR_QOS_LEN 2


struct ieee8022 {
	uint8_t    dsap;
	uint8_t    ssap;
	uint8_t    control;
	uint8_t    oui[3];
	uint16_t   type;
} __attribute__ ((packed));
#define DOT2HDR_LEN sizeof(struct ieee8022)

#define IEEE8022_SNAP 0xaa
#define IEEE8022_TYPE_IP 0x0800
#define IEEE8022_TYPE_DOT1X 0x888e
#define IEEE8022_TYPE_ARP 0x0806


#endif
