/*
 * jduck's fake AP for WiFi hax.
 *
 * by Joshua J. Drake (@jduck) on 2017-06-13
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

/* hi-res time */
#include <time.h>

/* internet networking / packet sending */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
//#include <arpa/inet.h>

/* packet capturing */
#include <pcap/pcap.h>


/* global hardcoded parameters */
#define SNAPLEN 1500
#define BEACON_INTERVAL 100
#define DEFAULT_CHANNEL 1


/* some bits borrowed from tcpdump! thanks guys! */
#define T_MGMT 0x0  /* management */
#define T_CTRL 0x1  /* control */
#define T_DATA 0x2  /* data */
#define T_RESV 0x3  /* reserved */

#define ST_BEACON 8

#define IEEE80211_RADIOTAP_RATE 2

#define IEEE80211_BROADCAST_ADDR "\xff\xff\xff\xff\xff\xff"


const char *dot11_types[4] = { "mgmt", "ctrl", "data", "resv" };
const char *dot11_subtypes[4][16] = {
	/* mgmt */
	{ "assoc-req", "assoc-resp",
		"re-assoc-req", "re-assoc-resp",
		"probe-req", "probe-resp",
		"6?", "7?",
		"beacon", "atim",
		"dis-assoc", "auth",
		"de-auth", "action",
		"14?", "15?" },
	/* ctrl */
	{ "0?", "1?", "2?", "3?", "4?", "5?", "6?", "7?",
		"8?", "block-ack", "ps-poll", "rts", "cts", "ack", "cf-end", "cf-end-ack" },
	/* data */
	{ "0?", "1?", "2?", "3?", "4?", "5?", "6?", "7?", "8?", "9?", "10?", "11?", "12?", "13?", "14?", "15?" },
	/* reserved */
	{ "0?", "1?", "2?", "3?", "4?", "5?", "6?", "7?", "8?", "9?", "10?", "11?", "12?", "13?", "14?", "15?" }
};

u_int8_t g_bssid[ETH_ALEN];
u_int8_t g_channel = DEFAULT_CHANNEL;


struct ieee80211_radiotap_header {
	u_int8_t it_version;     /* set to 0 */
	u_int8_t it_pad;
	u_int16_t it_len;         /* entire length */
	u_int32_t it_present;     /* fields present */
} __attribute__((__packed__));
typedef struct ieee80211_radiotap_header radiotap_t;

struct ieee80211_frame_header {
	u_int version:2;
	u_int type:2;
	u_int subtype:4;
	u_int8_t ctrlflags;
	u_int16_t duration;
	u_int8_t dst_mac[ETH_ALEN];
	u_int8_t src_mac[ETH_ALEN];
	u_int8_t bssid[ETH_ALEN];
	u_int seq:12;
	u_int frag:4;
} __attribute__((__packed__));
typedef struct ieee80211_frame_header dot11_frame_t;

struct ieee80211_beacon {
	u_int64_t timestamp;
	u_int16_t interval;
	u_int16_t caps;
} __attribute__((__packed__));
typedef struct ieee80211_beacon beacon_t;

struct ieee80211_information_element {
	u_int8_t id;
	u_int8_t len;
	u_int8_t *data[0];
} __attribute__((__packed__));
typedef struct ieee80211_information_element ie_t;


void hexdump(const u_char *ptr, u_int len);
int start_pcap(pcap_t **pcap, char *iface);
int open_raw_socket(char *iface);
int send_beacon(int sock, char *ssid);


void usage(char *argv0)
{
	fprintf(stderr, "usage: %s [options] <ssid>\n", argv0);
	fprintf(stderr, "\nsupported options:\n\n"
			"-c <channel>   use the specified channel (default: %d)\n"
			"-i <interface> interface to use for monitoring/injection (default: mon0)\n"
			, DEFAULT_CHANNEL
		   );
}


/*
 * The main function of this program simply checks prelimary arguments and
 * and launches the attack.
 */
int main(int argc, char *argv[])
{
	char *argv0;
	char iface[64] = { 0 };
	char ssid[32] = { 0 };
	int ret = 0, c, sock;
	pcap_t *pch = NULL;

	struct pcap_pkthdr *pchdr = NULL;
	const u_char *inbuf = NULL;
	int pcret;

	struct timespec last_beacon;


	/* initalize stuff */
	memset(&last_beacon, 0, sizeof(last_beacon));
	srand(getpid());

	argv0 = "jfap";
	if (argv && argc > 0 && argv[0])
		argv0 = argv[0];

	if (argc < 2) {
		usage(argv0);
		return 1;
	}

	strcpy(iface, "mon0");

	while ((c = getopt(argc, argv, "c:i:")) != -1) {
		switch (c) {
			case '?':
			case 'h':
				usage(argv0);
				return 1;

			case 'c':
				{
					int tmp = atoi(optarg);
					if (tmp < 1 || tmp > 12) {
						fprintf(stderr, "[!] invalid channel: %s\n", optarg);
						return 1;
					}

					g_channel = tmp;
				}
				break;

			case 'i':
				strncpy(iface, optarg, sizeof(iface) - 1);
				break;

			default:
				fprintf(stderr, "[!] invalid option '%c'! try -h ...\n", c);
				return 1;
				/* not reached */
				break;
		}
	}

	/* adjust params */
	argc -= optind;
	argv += optind;

	/* process required arguments */
	if (argc < 1) {
		usage(argv0);
		return 1;
	}

	strncpy(ssid, argv[0], sizeof(ssid) - 1);

	printf("[*] Starting access point with SSID \"%s\" via interface \"%s\"\n",
			ssid, iface);

	if (!start_pcap(&pch, iface))
		return 1;

	sock = open_raw_socket(iface);
	if (sock == -1)
		return 1;

	while (1) {
		pcret = pcap_next_ex(pch, &pchdr, &inbuf);

		/* if we got a packet, process it */
		if (pcret == 1) {
			radiotap_t *prt = (radiotap_t *)inbuf;
#ifdef DEBUG_RADIOTAP_PRESENT
			int idx = 0;
			u_int32_t *pu = &prt->it_present;
#endif
			const u_char *data;
			u_int32_t left;
			dot11_frame_t *d11;

			/* check the length against the capture length */
			if (pchdr->len > pchdr->caplen)
				fprintf(stderr, "[-] WARNING: truncated frame! (len: %lu > caplen: %lu)\n",
						(ulong)pchdr->len, (ulong)pchdr->caplen);

			/* process the radiotap header */
#ifdef DEBUG_RADIOTAP
			printf("[*] got RADIOTAP packet - ver:%u pad:%u len:%u\n",
					prt->it_version, prt->it_pad, prt->it_len);
#endif
#ifdef DEBUG_RADIOTAP_PRESENT
			printf("    present[%u]: 0x%lx\n", idx, (ulong)prt->it_present);
			while (prt->it_present & 0x1) {
				++idx;
				printf("    present[%u]: 0x%lx\n", idx, (ulong)pu[idx]);
			}
#endif
			if (prt->it_len >= pchdr->caplen) {
				fprintf(stderr, "[!] captured frame has no data?\n");
				continue;
			}

			/* prepare the reset of the data for processing */
			data = inbuf + prt->it_len;
			left = pchdr->caplen - prt->it_len;

			/* process the 802.11 frame */
			if (left < sizeof(*d11)) {
				fprintf(stderr, "[-] Not enough data for 802.11 frame header!\n");
				continue;
			}
			d11 = (dot11_frame_t *)data;
			if (d11->type != T_DATA
				&& !(d11->type == T_MGMT && d11->subtype == ST_BEACON)) {
				printf("[*] 802.11 packet ver:%u type:%s subtype:%s\n",
						d11->version, dot11_types[d11->type],
						dot11_subtypes[d11->type][d11->subtype]);
				hexdump(data, pchdr->caplen - prt->it_len);
#ifdef DEBUG_DATA
			} else {
				printf("[*] 802.11 packet ver:%u type:%s subtype:%s%s\n",
						d11->version, dot11_types[d11->type],
						dot11_subtypes[d11->type][d11->subtype],
						(d11->subtype >> 3) ? " (QoS)" : "");
				hexdump(data, pchdr->caplen - prt->it_len);
#endif
			}
		} else {
			/* we didn't get a pcket yet, do periodic processing */
			struct timespec now, diff;

			if (clock_gettime(CLOCK_REALTIME, &now)) {
				perror("[!] gettimeofday failed");
				break;
			}

			/* see how long since the last beacon. if it's been long enough,
			 * send another */
			diff.tv_sec = now.tv_sec - last_beacon.tv_sec;
			diff.tv_nsec = now.tv_nsec - last_beacon.tv_nsec;
			if (diff.tv_nsec < 0) {
				--diff.tv_sec;
				diff.tv_nsec += 1000000000;
			}
			if (diff.tv_sec > 0 || diff.tv_nsec > BEACON_INTERVAL * 1000000) {
#ifdef DEBUG_BEACON_INTERVAL
				printf("%lu.%lu - %lu.%lu = %lu.%lu (vs %lu)\n",
						(ulong)now.tv_sec, now.tv_nsec,
						(ulong)last_beacon.tv_sec, last_beacon.tv_nsec,
						(ulong)diff.tv_sec, diff.tv_nsec,
						(ulong)BEACON_INTERVAL * 1000000);
#endif
				if (!send_beacon(sock, ssid))
					break;
				last_beacon = now;
			}
		}
	}

	pcap_close(pch);
	return ret;
}


/*
 * try to start capturing packets from the specified interface (a wireless card
 * in monitor mode)
 *
 * on succes, we return 1, on failure, 0
 */
int start_pcap(pcap_t **pcap, char *iface)
{
   char errorstr[PCAP_ERRBUF_SIZE];
   int datalink;

   printf("[*] Starting capture on \"%s\" ...\n", iface);

   *pcap = pcap_open_live(iface, SNAPLEN, 8, 25, errorstr);
   if (*pcap == (pcap_t *)NULL) {
	   fprintf(stderr, "[!] pcap_open_live() failed: %s\n", errorstr);
	   return 0;
   }

   datalink = pcap_datalink(*pcap);
   switch (datalink) {
	   case DLT_IEEE802_11_RADIO:
		   break;

	  default:
		   fprintf(stderr, "[!] Unknown datalink for interface \"%s\": %d\n",
				   iface, datalink);
		   fprintf(stderr, "    Only RADIOTAP is currently supported.\n");
		   return 0;
   }

   return 1;
}


/*
 * open a raw socket that we can use to send raw 802.11 frames
 */
int open_raw_socket(char *iface)
{
	int sock;
#ifdef DEBUG_IF_HWADDR
	int i;
#endif
    struct sockaddr_ll la;
    struct ifreq ifr;

	sock = socket(PF_PACKET, SOCK_RAW, ETH_P_ALL);
    if (sock == -1) {
		perror("[!] Unable to open raw socket");
		return -1;
	}

	/* build the link-level address struct for binding */
	memset(&la, 0, sizeof(la));
    la.sll_family = AF_PACKET;
    la.sll_halen = ETH_ALEN;

	/* get the interface index */
	memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
		perror("[!] Unable to get interface index");
		close(sock);
        return -1;
    }
#ifdef DEBUG_IF_INDEX
	printf("[*] Interface index: %u\n", ifr.ifr_ifindex);
#endif
    la.sll_ifindex = ifr.ifr_ifindex;

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
		perror("[!] Unable to get hardware address");
		close(sock);
        return (-1);
    }
#ifdef DEBUG_IF_HWADDR
	printf("[*] Interface hardware address: ");
	for (i = 0; i < ETH_ALEN; i++) {
		printf("%02X", ifr.ifr_hwaddr.sa_data[i] & 0xff);
		if (i < ETH_ALEN - 1)
			printf(":");
	}
	printf("\n");
#endif
	memcpy(g_bssid, ifr.ifr_hwaddr.sa_data, sizeof(g_bssid));
    memcpy(la.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	/* verify the interface uses RADIOTAP */
    if (ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_RADIOTAP) {
        fprintf(stderr, "[!] bad address family: %u\n", ifr.ifr_hwaddr.sa_family);
        close(sock);
		return -1;
    }

	/* bind this socket to the interface */
    if (bind(sock, (struct sockaddr *)&la, sizeof(la)) == -1) {
		perror("[!] Unable to bind to interface");
        close(sock);
        return -1;
    }
	return sock;
}


/*
 * send a beacon frame to announce our network
 */
int send_beacon(int sock, char *ssid)
{
	char pkt[4096], *p;
	radiotap_t *prt;
	dot11_frame_t *d11;
	beacon_t *bc;
	ie_t *ie;
	u_int8_t ssid_len = strlen(ssid);

	/* fill out the radio tap header */
	prt = (radiotap_t *)pkt;
	prt->it_version = 0;
	prt->it_len = sizeof(*prt) + 1;
	prt->it_present = (1 << IEEE80211_RADIOTAP_RATE);

	/* add the data rate (part of the radiotap header) */
	p = (char *)(prt + 1);
	*p++ = 0x4;  // 2Mb/s

	/* add the 802.11 header */
	d11 = (dot11_frame_t *)p;
	//d11->version = 0;
	d11->type = T_MGMT;
	d11->subtype = ST_BEACON;
	//d11->ctrlflags = 0;
	//d11->duration = 0;
	memcpy(d11->dst_mac, IEEE80211_BROADCAST_ADDR, ETH_ALEN);
	memcpy(d11->src_mac, g_bssid, ETH_ALEN);
	memcpy(d11->bssid, g_bssid, ETH_ALEN);
	d11->seq = 123;
	//d11->frag = 0;
	p = (char *)(d11 + 1);

	/* add the beacon info */
	bc = (beacon_t *)p;
	//bc->timestamp = 0;
	bc->interval = BEACON_INTERVAL;
	bc->caps = 1; // we are an AP ;-)
	p = (char *)(bc + 1);

	/* add the ssid IE */
	ie = (ie_t *)p;
	//ie->id = 0; // ssid
	ie->len = ssid_len;
	p = (char *)(ie + 1);
	memcpy(p, ssid, ssid_len);
	p += ssid_len;

	/* add the supported rate IE */
	ie = (ie_t *)p;
	ie->id = 1; // rates
	ie->len = 8; // # of rates supported
	p = (char *)(ie + 1);
	*p++ = 0x0c;
	*p++ = 0x12;
	*p++ = 0x18;
	*p++ = 0x24;
	*p++ = 0x30;
	*p++ = 0x48;
	*p++ = 0x60;
	*p++ = 0x6c;

	/* add the channel parameter (ds params) */
	ie = (ie_t *)p;
	ie->id = 3; // ds params
	ie->len = 1;
	p = (char *)(ie + 1);
	*p++ = g_channel;

#if 0
	/* add the RM capabilities */
	ie = (ie_t *)p;
	ie->id = 0x46; // rm capabilities
	ie->len = 5;
	p = (char *)(ie + 1);
	memset(p, 0xff, ie->len);
#endif

	if (send(sock, pkt, p - pkt, 0) == -1) {
		perror("[!] Unable to send beacon!");
		return 0;
	}

	//printf("[*] Sent beacon!\n");

	return 1;
}
