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
#include <netinet/ether.h>
#include <linux/if.h>
#include <linux/if_packet.h>

/* packet capturing */
#include <pcap/pcap.h>


/* global hardcoded parameters */
#define SNAPLEN 4096
#define BEACON_INTERVAL 500
#define DEFAULT_CHANNEL 1


/* some bits borrowed from tcpdump! thanks guys! */
#define T_MGMT 0x0  /* management */
#define T_CTRL 0x1  /* control */
#define T_DATA 0x2  /* data */
#define T_RESV 0x3  /* reserved */

#define ST_ASSOC_REQ 0
#define ST_ASSOC_RESP 1
#define ST_PROBE_REQ 4
#define ST_PROBE_RESP 5
#define ST_BEACON 8
#define ST_AUTH 11

#define IEID_SSID 0
#define IEID_RATES 1
#define IEID_DSPARAMS 3

#define IEEE80211_RADIOTAP_RATE 2

#define IEEE80211_BROADCAST_ADDR ((u_int8_t *)"\xff\xff\xff\xff\xff\xff")


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
u_int8_t g_ssid[32];
u_int8_t g_ssid_len;
u_int8_t g_channel = DEFAULT_CHANNEL;

/* global options */
int g_send_beacons = 0;


struct ieee80211_radiotap_header {
	u_int8_t it_version;      /* set to 0 */
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
	u_int frag:4;
	u_int seq:12;
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
	u_int8_t data[0];
} __attribute__((__packed__));
typedef struct ieee80211_information_element ie_t;

struct ieee80211_authentication {
	u_int16_t algorithm;
	u_int16_t seq;
	u_int16_t status;
} __attribute__((__packed__));
typedef struct ieee80211_authentication auth_t;

struct ieee80211_assoc_response {
	u_int16_t caps;
	u_int16_t status;
	u_int16_t id;
} __attribute__((__packed__));
typedef struct ieee80211_assoc_response assoc_resp_t;


char *mac_string(u_int8_t *mac);
void hexdump(const u_char *ptr, u_int len);

ie_t *get_ssid_ie(const u_int8_t *data, u_int32_t left);
u_int16_t get_sequence(void);

int start_pcap(pcap_t **pcap, char *iface);
int open_raw_socket(char *iface);

int send_beacon(int sock);
int send_probe_response(int sock, u_int8_t *dst_mac);
int send_auth_response(int sock, u_int8_t *dst_mac);
int send_assoc_response(int sock, u_int8_t *dst_mac);


void usage(char *argv0)
{
	fprintf(stderr, "usage: %s [options] <ssid>\n", argv0);
	fprintf(stderr, "\nsupported options:\n\n"
			"-b             send beacons regularly (default: off)\n"
			"-c <channel>   use the specified channel (default: %d)\n"
			"-i <interface> interface to use for monitoring/injection (default: mon0)\n"
			"-m <mac addr>  use the specified mac address (default: from phys)\n"
			, DEFAULT_CHANNEL);
}


/*
 * The main function of this program simply checks prelimary arguments and
 * and launches the attack.
 */
int main(int argc, char *argv[])
{
	char *argv0;
	char iface[64] = { 0 };
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

	while ((c = getopt(argc, argv, "bc:i:m:")) != -1) {
		switch (c) {
			case '?':
			case 'h':
				usage(argv0);
				return 1;

			case 'b':
				g_send_beacons = 1;
				break;

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

			case 'm':
				{
					struct ether_addr *pe;

					pe = ether_aton(optarg);
					if (!pe) {
						fprintf(stderr, "[!] invalid mac address: %s\n", optarg);
						return 1;
					}
					memcpy(g_bssid, pe->ether_addr_octet, ETH_ALEN);
				}
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

	strncpy((char *)g_ssid, argv[0], sizeof(g_ssid) - 1);
	g_ssid_len = strlen((char *)g_ssid);

	printf("[*] Starting access point with SSID \"%s\" via interface \"%s\"\n",
			g_ssid, iface);

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
#ifdef DEBUG_DOT11_SHORT_PKTS
				fprintf(stderr, "[-] Not enough data for 802.11 frame header!\n");
				printf("bytes left: %u\n", left);
				hexdump(data, left);
#endif
				continue;
			}
			d11 = (dot11_frame_t *)data;

			/* ignore anything from us */
			if (!memcmp(d11->src_mac, g_bssid, ETH_ALEN))
				continue;

			/* prepare further processing */
			data = (const u_char *)(d11 + 1);
			left -= sizeof(*d11);

			/* if it's a probe request, see if it's for us */
			if (d11->type == T_MGMT) {
				if (d11->subtype == ST_BEACON) {
					/* ignore beacons */
					continue;
				} else if (d11->subtype == ST_PROBE_REQ) {
					ie_t *ie = get_ssid_ie(data, left);
					char ssid_req[32] = { 0 };

					if (!ie)
						continue;
					if (ie->len > 0) {
						if (ie->len > sizeof(ssid_req) - 1)
							strncpy(ssid_req, (char *)ie->data, sizeof(ssid_req) - 1);
						else
							strncpy(ssid_req, (char *)ie->data, ie->len);
						printf("[*] (%s) Probe request for SSID (%u bytes): \"%s\"\n", mac_string(d11->src_mac), ie->len, ssid_req);
					}

					if (!memcmp(d11->dst_mac, g_bssid, ETH_ALEN)) {
#define CHECK_SSID
#ifdef CHECK_SSID
						/* for us!? */
						if (!strcmp(ssid_req, (char *)g_ssid)) {
							printf("[*] (%s) Probe request for our BSSID and SSID, replying...\n", mac_string(d11->src_mac));
							if (!send_probe_response(sock, d11->src_mac))
								continue;
						}
#else
						printf("[*] (%s) Probe request for our BSSID, replying...\n", mac_string(d11->src_mac));
						if (!send_probe_response(sock, d11->src_mac))
							continue;
#endif
					} else if (!memcmp(d11->dst_mac, IEEE80211_BROADCAST_ADDR, ETH_ALEN)) {
						/* broadcast probe request - discovery? */
						if (ie && ie->len > 0) {
							if (!strcmp(ssid_req, (char *)g_ssid)) {
								printf("[*] (%s) Broadcast probe request for our SSID \"%s\" received, replying...\n", mac_string(d11->src_mac), ssid_req);
								if (!send_probe_response(sock, d11->src_mac))
									continue;
							} else {
								printf("[*] (%s) Broadcast probe request for \"%s\" received, NOT replying...\n", mac_string(d11->src_mac), ssid_req);
							}
						} else {
							printf("[*] (%s) Broadcast probe request received, replying...\n", mac_string(d11->src_mac));
							if (!send_probe_response(sock, d11->src_mac))
								continue;
						}
					} /* mac check */
					continue;
				} else if (d11->subtype == ST_AUTH) {
					if (!memcmp(d11->dst_mac, g_bssid, ETH_ALEN)) {
						printf("[*] (%s) Auth request received, replying...\n", mac_string(d11->src_mac));
						if (!send_auth_response(sock, d11->src_mac))
							continue;
					} else {
						printf("[*] (%s) Auth request for another BSSID received, NOT replying...\n", mac_string(d11->src_mac));
						printf("    DST MAC: %s\n", mac_string(d11->dst_mac));
						printf("    BSSID: %s\n", mac_string(d11->bssid));
					}
					continue;
				} else if (d11->subtype == ST_ASSOC_REQ) {
					if (!memcmp(d11->dst_mac, g_bssid, ETH_ALEN)) {
						printf("[*] (%s) Association request received, replying...\n", mac_string(d11->src_mac));
						if (!send_assoc_response(sock, d11->src_mac))
							continue;
					} else {
						printf("[*] (%s) Association request for another BSSID received, replying...\n", mac_string(d11->src_mac));
						printf("    DST MAC: %s\n", mac_string(d11->dst_mac));
						printf("    BSSID: %s\n", mac_string(d11->bssid));
					}
					continue;
				} /* subtype check */
			} /* type check */

			/* if we didn't handle this packet somehow, we should display it */
			else if (d11->type == T_DATA) {
#ifdef DEBUG_DATA
				printf("[*] Unhandled 802.11 packet ver:%u type:%s subtype:%s%s\n",
						d11->version, dot11_types[d11->type],
						dot11_subtypes[d11->type][d11->subtype],
						(d11->subtype >> 3) ? " (QoS)" : "");
				hexdump(data, pchdr->caplen - prt->it_len);
#endif
				continue;
			}

#ifdef DEBUG_DOT11
			printf("[*] Unhandled 802.11 packet ver:%u type:%s subtype:%s\n",
					d11->version, dot11_types[d11->type],
					dot11_subtypes[d11->type][d11->subtype]);
			hexdump(data, pchdr->caplen - prt->it_len);
#endif
		} else {
			if (g_send_beacons) {
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
					if (!send_beacon(sock))
						break;
					last_beacon = now;
				}
			} /* if (g_send_beacons) */
		} /* if (got_packet) */
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
		return -1;
	}
#ifdef DEBUG_IF_HWADDR
	printf("[*] Interface hardware address: %s\n", mac_string((u_int8_t *)ifr.ifr_hwaddr.sa_data));
#endif
	if (!memcmp(g_bssid, "\x00\x00\x00\x00\x00\x00", ETH_ALEN))
		memcpy(g_bssid, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
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
 * send an 802.11 packet with a bunch of re-transmissions for the fuck of it
 */
int send_packet(int sock, u_int8_t *pkt, size_t len, dot11_frame_t *d11)
{
#ifdef RETRANSMIT
	int i;
#endif

	if (send(sock, pkt, len, 0) == -1) {
		perror("[!] Unable to send beacon!");
		return 0;
	}

#ifdef RETRANSMIT
	/* set the retransmit flag on the 802.11 header */
	d11->ctrlflags |= 8; // retry

	/* send it again.. */
	for (i = 0; i < 10; i++) {
		usleep(100);
		if (send(sock, pkt, len, 0) == -1) {
			perror("[!] Unable to send beacon!");
			return 0;
		}
	}
#endif
	return 1;
}


/*
 * fill the radio tap header in for a packet
 */
void fill_radiotap(u_int8_t **ppkt)
{
	u_int8_t *p = *ppkt;
	radiotap_t *prt = (radiotap_t *)p;

	/* fill out the radio tap header */
	prt->it_version = 0;
	prt->it_len = sizeof(*prt) + 1;
	prt->it_present = (1 << IEEE80211_RADIOTAP_RATE);

	p += sizeof(radiotap_t);

	/* add the data rate (data of the radiotap header) */
	*p++ = 0x4;  // 2Mb/s

	*ppkt = p;
}


/*
 * fill the 802.11 frame header
 */
void fill_dot11(u_int8_t **ppkt, u_int8_t type, u_int8_t subtype, u_int8_t *dst_mac)
{
	dot11_frame_t *d11 = (dot11_frame_t *)(*ppkt);

	/* add the 802.11 header */
	//d11->version = 0;
	d11->type = type;
	d11->subtype = subtype;
	//d11->ctrlflags = 0;
	//d11->duration = 0;
	memcpy(d11->dst_mac, dst_mac, ETH_ALEN);
	memcpy(d11->src_mac, g_bssid, ETH_ALEN);
	memcpy(d11->bssid, g_bssid, ETH_ALEN);
	d11->seq = get_sequence();
	//d11->frag = 0;

	*ppkt += sizeof(dot11_frame_t);
}


/*
 * fill in an information element
 */
void fill_ie(u_int8_t **ppkt, u_int8_t id, u_int8_t *data, u_int8_t len)
{
	u_int8_t *p = *ppkt;
	ie_t *ie = (ie_t *)p;

	/* add the ssid IE */
	ie->id = id;
	ie->len = len;

	p = (u_int8_t *)(ie + 1);
	memcpy(p, data, len);

	p += len;
	*ppkt = p;
}


/*
 * send a beacon frame to announce our network
 */
int send_beacon(int sock)
{
	u_int8_t pkt[4096] = { 0 }, *p = pkt;
	beacon_t *bc;

	fill_radiotap(&p);
	fill_dot11(&p, T_MGMT, ST_BEACON, IEEE80211_BROADCAST_ADDR);

	/* add the beacon info */
	bc = (beacon_t *)p;
	//bc->timestamp = 0;
	bc->interval = BEACON_INTERVAL;
	bc->caps = 1; // we are an AP ;-)
	p = (u_int8_t *)(bc + 1);

	fill_ie(&p, IEID_SSID, g_ssid, g_ssid_len);
	fill_ie(&p, IEID_RATES, (u_int8_t *)"\x0c\x12\x18\x24\x30\x48\x60\x6c", 8);
	fill_ie(&p, IEID_DSPARAMS, &g_channel, 1);

	/* don't retransmit beacons */
	if (send(sock, pkt, p - pkt, 0) == -1) {
		perror("[!] Unable to send beacon!");
		return 0;
	}

	//printf("[*] Sent beacon!\n");
	return 1;
}


/*
 * send a probe response to the specified sender
 */
int send_probe_response(int sock, u_int8_t *dst_mac)
{
	u_int8_t pkt[4096] = { 0 }, *p = pkt;
	dot11_frame_t *d11;
	beacon_t *bc;

	fill_radiotap(&p);
	d11 = (dot11_frame_t *)p;
	fill_dot11(&p, T_MGMT, ST_PROBE_RESP, dst_mac);

	/* add the beacon info */
	bc = (beacon_t *)p;
	//bc->timestamp = 0;
	bc->interval = BEACON_INTERVAL;
	bc->caps = 1; // we are an AP ;-)
	p = (u_int8_t *)(bc + 1);

	fill_ie(&p, IEID_SSID, g_ssid, g_ssid_len);
	fill_ie(&p, IEID_RATES, (u_int8_t *)"\x0c\x12\x18\x24\x30\x48\x60\x6c", 8);
	fill_ie(&p, IEID_DSPARAMS, &g_channel, 1);

	if (!send_packet(sock, pkt, p - pkt, d11))
		return 0;

	//printf("[*] Sent probe response to %s!\n", mac_string(dst_mac));
	return 1;
}


/*
 * send an authentication response
 */
int send_auth_response(int sock, u_int8_t *dst_mac)
{
	u_int8_t pkt[4096] = { 0 }, *p = pkt;
	dot11_frame_t *d11;
	auth_t *auth;

	fill_radiotap(&p);
	d11 = (dot11_frame_t *)p;
	fill_dot11(&p, T_MGMT, ST_AUTH, dst_mac);

	/* add the auth info */
	auth = (auth_t *)p;
	//auth->algorithm = 0; // AUTH_OPEN;
	auth->seq = 2; // should be responding to auth seq 1
	//auth->status = 0; // successful
	p = (u_int8_t *)(auth + 1);

	if (!send_packet(sock, pkt, p - pkt, d11))
		return 0;

	//printf("[*] Sent auth response to %s!\n", mac_string(dst_mac));
	return 1;
}


/*
 * send an association response
 */
int send_assoc_response(int sock, u_int8_t *dst_mac)
{
	u_int8_t pkt[4096] = { 0 }, *p = pkt;
	dot11_frame_t *d11;
	assoc_resp_t *assoc;

	fill_radiotap(&p);
	d11 = (dot11_frame_t *)p;
	fill_dot11(&p, T_MGMT, ST_ASSOC_RESP, dst_mac);

	/* add the assoc info */
	assoc = (assoc_resp_t *)p;
	assoc->caps = 1;
	//assoc->status = 0; // successful
	assoc->id = 1;
	p = (u_int8_t *)(assoc + 1);

	fill_ie(&p, IEID_RATES, (u_int8_t *)"\x0c\x12\x18\x24\x30\x48\x60\x6c", 8);

	if (!send_packet(sock, pkt, p - pkt, d11))
		return 0;

	//printf("[*] Sent association response to %s!\n", mac_string(dst_mac));
	return 1;
}


/*
 * process the information elements looking for an SSID
 */
ie_t *get_ssid_ie(const u_int8_t *data, u_int32_t left)
{
	ie_t *ie;
	const u_int8_t *p = data;
	u_int32_t rem = left;

#ifdef DEBUG_GET_SSID_IE
	printf("[*] processing information element data:\n");
	hexdump(data, left);
#endif

	while (rem > 0) {
		/* see if we have enough for the IE header */
		if (rem < sizeof(*ie)) {
			fprintf(stderr, "[-] Not enough data for an IE!\n");
			return NULL;
		}

		ie = (ie_t *)p;

		/* advance... */
		p += sizeof(*ie);
		rem -= sizeof(*ie);

		/* now, is it an SSID ? */
		if (ie->id == IEID_SSID) {
			return ie;
		}

		/* check if we have all the data */
		if (rem < ie->len) {
			fprintf(stderr, "[-] Not enough data for the IE's data!\n");
			return NULL;
		}

		/* advance past the ie->data */
		p += ie->len;
		rem -= ie->len;
	}

#ifdef DEBUG_GET_SSID_IE
	fprintf(stderr, "[-] SSID IE not found!\n");
#endif
	return NULL;
}


/*
 * create the ascii representation of the specified mac address
 */
char *mac_string(u_int8_t *mac)
{
	static char mac_str[32];
	char *p = mac_str;
	int i;

	for (i = 0; i < ETH_ALEN; i++) {
		u_int8_t hi = mac[i] >> 4;
		u_int8_t lo = mac[i] & 0xf;

		if (hi > 9)
			*p++ = hi - 10 + 'a';
		else
			*p++ = hi + '0';
		if (lo > 9)
			*p++ = lo - 10 + 'a';
		else
			*p++ = lo + '0';
		if (i < ETH_ALEN - 1)
			*p++ = ':';
	}
	*p = '\0';

	return mac_str;
}


/*
 * handle sequence number generation
 */
u_int16_t get_sequence(void)
{
	static u_int16_t sequence = 1337;
	uint16_t ret = sequence;

	sequence++;
	if (sequence > 4095)
		sequence = 0;
	return ret;
}
