/**
 * \file main.c
 *
 * \brief Filter DNS requests as a brute force way of cutting down on the amount
 *        of advertisements when web browsing.
 *
 * Brute force filter all DNS requests by intercepting them using the Darwin ipfw
 * packet divert functionality and then send back fake not found responses to
 * requests that match provided blacklists.
 *
 * Copyright 2009 Craig Newell <craign@ieee.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <stringlist.h>
#include <errno.h>


/* global program state */
static volatile bool go = true;        ///< active and processing packets
static StringList *bl;                ///< blacklist

/* command line options */
static bool verbose = false;        ///< print out useful tracing to verify operation
static int divert_port_num = 5432;    ///< divert socket port number
static int ipfw_rule_num = 31026;    ///< ipfw firewall rule number for DNS divert entry


/**
 * \brief Catch signals so that we can shutdown orderly and remove the added
 *        firewall rules.
 * \param[in] s signal number caught
 */
static void
signal_handler(int s)
{
    (void)s;

    /* signal orderly shutdown */
    go = false;
}


/**
 * \brief Compare a blacklist entry against a fully qualified host name.
 *
 * \param[in] blacklist_entry    Blacklist entry to check host name against.
 * \param[in] fqhn                Fully qualified host name to check.
 * \retval                        true if host name matches blacklist entry.
 */
static bool
compare_entries(const char *blacklist_entry, const char *fqhn)
{
    /* match from end */
    const char *fe = strchr(fqhn, '\0');
    const char *be = strchr(blacklist_entry, '\0');

    /* fqhn is shorter than blacklist_entry */
    if ((be - blacklist_entry) > (fe - fqhn))
        return false;

    /* nulls will always match so skip them */
    fe--;
    be--;

    while (true) {

        /* character mismatch */
        if (*be != *fe)
            return false;

        /* matched up to end of blacklist_entry */
        if (be == blacklist_entry)
            break;

        be--;
        fe--;
    }

    if (fe == fqhn)    /* exact match */
        return true;

    fe--;
    if (*fe == '.')    /* prefix match */
        return true;

    return false;
}


/**
 * \brief Filter comments, extra whitespace, etc from blacklist or hosts file line
 *
 * \param[in] line possibly containing a blacklist rule.
 * \retval blacklist rule string or NULL if line does not contain a valid rule.
 */
static char *
cleanup_entry(char *line)
{
    // skip everthing after the '#' comment marker
    char *cp = strchr(line, '#');
    if (cp)
        *cp = '\0';

    // skip leading whitespace
    while (isspace(*line))
        line++;

    // skip trailing whitespace
    cp = strchr(line, '\0');
    cp--;
    while (cp > line && isspace(*cp))
        *cp-- = '\0';

    // skip empty lines
    if (*line == '\0')
        return NULL;

    /* if this is a host file, skip the IP address */
    struct in_addr ia;
    if (inet_aton(line, &ia) == 1) {

        /* is it 127.0.0.1 or 0.0.0.0? */
        if ((ia.s_addr != htonl(INADDR_LOOPBACK)) &&
            (ia.s_addr != htonl(INADDR_ANY)))
            return NULL;

        /* skip IP address */
        cp = strchr(line, ' ');
        if (!cp)
            cp = strchr(line, '\t');
        if (!cp) {
            fprintf(stderr, "\nWARNING: invalid host entry <%s>", line);
            return NULL;
        }
        line = cp + 1;

        // skip remaining leading whitespace
        while (isspace(*line))
            line++;
    }

    /* convert to lowercase */
    cp = line;
    while (*cp) {

        /* make it lowercase */
        *cp = tolower(*cp);

        /* check for invalid characters */
        if (!(isalnum(*cp) || *cp == '.' || *cp == '-' || *cp == '_')) {
            fprintf(stderr, "\nWARNING: invalid blacklist entry <%s>", line);
            return NULL;
        }

        cp++;
    }

    /* make it fully qualified */
    cp = strchr(line, '\0');
    cp--;
    if (*cp != '.')
        strcat(cp, ".");

    return line;
}


/**
 * \brief Add entries from a blacklist file to the current blacklist.
 *
 * \param[in] filename filename of hosts to block in blacklist or hosts format.
 */
static void
load_blacklist(const char *filename)
{
    if (!bl)
        bl = sl_init();

    if (verbose) {
        printf("Loading <%s> ...", filename);
        fflush(stdout);
    }

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen");
        return;
    }

    int n = 0;
    while (true) {
        /* read line from file */
        char lbuf[256];
        char *line = fgets(lbuf, sizeof lbuf, fp);
        if (!line)
            break;

        /* cleanup comments, whitespace, etc. */
        line = cleanup_entry(line);
        if (!line)
            continue;

        /* check for duplicate */
        for (size_t i=0; i < bl->sl_cur; i++) {
            if (compare_entries(bl->sl_str[i], line)) {
                if (verbose)
                    fprintf(stderr, "\nWARNING: duplicate blacklist entry <%s> matches <%s>",
                            line, bl->sl_str[i]);

                /* add the more general one to the list */
                if (strlen(bl->sl_str[i]) > strlen(line)) {
                    free(bl->sl_str[i]);
                    bl->sl_str[i] = strdup(line);
                }

                /* all done */
                line = NULL;
                break;
            }
        }

        /* add to blacklist */
        if (line) {
            // fprintf(stderr, "blacklisting %s\n", line);
            sl_add(bl, strdup(line));
            n++;
        }
    }

    fclose(fp);

    if (verbose)
        printf(" added %d blacklist entries ...\n", n);
}


/**
 * Check the blacklist for the given domain
 *
 * \param[in] fqhn fully qualified host name to test.
 * \return           true if hostname is blacklisted.
 */
static bool
is_blacklisted(char *fqhn)
{
    /* convert to lower case just in case */
    char lc_fqhn[255];
    char *l = lc_fqhn;
    while (*fqhn)
        *l++ = tolower(*fqhn++);
    *l = '\0';

    /* Mac OS X first requests a "A" record and then a "AAAA" record
     * so a simple single element cache works quite well */
    static char *last_hit = NULL;
    if (last_hit && compare_entries(last_hit, lc_fqhn))
        return true;

    /* simple lookup */
    for (size_t i=0; i < bl->sl_cur; i++) {
        if (compare_entries(bl->sl_str[i], lc_fqhn)) {
            last_hit = bl->sl_str[i];
            return true;
        }
    }

    return false;
}


#ifdef TRACE
/**
 * Generates a hexdump of a memory area.
 *
 * \param  mem     pointer to memory to dump
 * \param  length  how many bytes to dump
 */
static void
hexdump(void *mem, unsigned length)
{
    char line[80];
    const char *src = (const char *)mem;

    printf("%p (%u bytes)\r\n"
           "       0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF\r\n"
           , src, length);

    for (unsigned i=0; i<length; i+=16, src+=16) {
        char *t = line;

        /* print hex */
        t += sprintf(t, "%04x:  ", i);
        for (int j=0; j<16; j++) {
            if (i+j < length)
                t += sprintf(t, "%02X", src[j] & 0xff);
            else
                t += sprintf(t, "  ");
            t += sprintf(t, j%2 ? " " : "-");
        }

        /* print printable characters */
        t += sprintf(t, "  ");
        for (int j=0; j<16; j++) {
            if (i+j < length) {
                if (isprint((unsigned char)src[j]))
                    t += sprintf(t, "%c", src[j]);
                else
                    t += sprintf(t, ".");
            } else {
                t += sprintf(t, " ");
            }
        }

        printf("%s\r\n", line);
    }
}
#else
#define    hexdump(x, y)
#endif


/**
 * \brief Calculate the IPv4 header checksum (assumes that checksum field has been set to zero)
 *
 * \param[in] data    IPv4 header to checksum
 * \param[in] len    length of header to checksum in bytes
 * \retval    checksum read to be set in IPv4 header
 */
static unsigned short
iphdr_checksum(const unsigned short *data, unsigned int len)
{
    long csum = 0;
    while (len > 1) {
        csum += ntohs(*data++);
        if (csum & 0x80000000)
            csum = (csum & 0xffff) + (csum >> 16);
        len -= 2;
    }
    while (csum >> 16)
        csum = (csum & 0xffff) + (csum >> 16);
    return ~csum;
}


/**
 * \brief Process an IP packet containing a DNS request
 *
 * \param[in] ipbuf     Raw bytes of the IP packet to process
 * \param[in] ipbuf_len Length in bytes of the IP packet
 */
static void
process_ip(unsigned char *ipbuf, int ipbuf_len)
{
    /* IP header */
    struct ip *ip = (struct ip *)&ipbuf[0];

    /* only know how to handle IPv4 */
    if (ip->ip_v != 4)
        return;

    /* check that we have all the IP header */
    const int ip_hl = ip->ip_hl << 2;
    if (ipbuf_len < ip_hl)
        return;

    /* debugging */
    //    fprintf(stderr, "\tip from %s", addr2ascii(AF_INET, &ip->ip_src, sizeof(ip->ip_src), NULL));
    //    fprintf(stderr, " to %s\n", addr2ascii(AF_INET, &ip->ip_dst, sizeof(ip->ip_dst), NULL));

    /* UDP header */
    struct udphdr *udp = (struct udphdr *)&ipbuf[ip_hl];
    uint ubuf_len = ipbuf_len - ip_hl;

    /* check that we have all the UDB header*/
    if (ubuf_len < sizeof(struct udphdr))
        return;

    /* debugging */
    //    fprintf(stderr, "\tudp from %d to %d len %d\n",
    //            ntohs(udp->uh_sport), ntohs(udp->uh_dport), ntohs(udp->uh_ulen));

    /* check dest port */
    if (ntohs(udp->uh_dport) != 53)
        return;

    /* check that we have all the UDP data */
    if (ubuf_len < ntohs(udp->uh_ulen))
        return;

    /* DNS message */
    unsigned char *dns = &ipbuf[ip_hl + sizeof(struct udphdr)];
    int dns_len = (int)ntohs(udp->uh_ulen) - (int)sizeof(struct udphdr);
    hexdump(dns, dns_len);

    /* check that we have all the DNS header */
    if (dns_len < 12)
        return;

    /* decode DNS header */
    const int qdcount = dns[5] + (dns[4] << 8);
    const int ancount = dns[7] + (dns[6] << 8);
    const int nscount = dns[9] + (dns[8] << 8);
    const int arcount = dns[11] + (dns[10] << 8);

    /* debugging */
    //    printf("\tdns id %d qdcount %d ancount %d nscount %d arcount %d\n",
    //           (dns[1] + (dns[0] << 8)),
    //           qdcount, ancount, nscount, arcount);

    /* we only handle simple queries */
    if (dns[2] & 0x80)                        /* this is a response packet */
        return;
    if ((dns[2] >> 3) != 0)                    /* this is standard query */
        return;
    if (qdcount != 1 || ancount != 0 ||        /* this is a simple query */
        nscount != 0 || arcount != 0)
        return;

    /* extract out the query */
    char qbuf[255];
    int i = 12, j = 0;
    while (dns[i]) {
        memcpy(&qbuf[j], &dns[i+1], dns[i]);
        j += dns[i];
        i += dns[i] + 1;
        qbuf[j++] = '.';
    }
    qbuf[j] = '\0';
    i++;
    const int qtype = dns[i+1] + (dns[i+0] << 8);
    const int qclass = dns[i+3] + (dns[i+2] << 8);

    /* debugging */
    //    printf("\tquery \"%s\" qtype %d qclass %d\n",
    //           qbuf, qtype, qclass);

    /* we only handle simple A IPv4 and simple AAAA IPv6 queries */
    if (!((qtype == 1) || (qtype == 28)))        /* A or AAAA */
        return;
    if (qclass != 1)                            /* IN */
        return;

    /* is this full qualified host name blacklisted? */
    if (!is_blacklisted(qbuf))
        return;

    /* debugging */
    if (verbose)
        fprintf(stderr, "blacklisted %s (IPv%c)\n", qbuf, (qtype == 1) ? '4' : '6');

    /* mark as not found */
    dns[2] |= 0x85;
    dns[3] |= 0x83;    /* RA + RCODE = 3 */

    /* update UDP header for reply (swap ports) */
    unsigned short ts = udp->uh_sport;
    udp->uh_sport = udp->uh_dport;
    udp->uh_dport = ts;
    udp->uh_sum = 0;                    /* no need for checksum as all local */

    /* update IP header for reply (swap addresses) */
    struct in_addr ti = ip->ip_src;
    ip->ip_src = ip->ip_dst;
    ip->ip_dst = ti;
    ip->ip_sum = 0;
    ip->ip_sum = htons(iphdr_checksum((const unsigned short *)ip, ip_hl));
}


/**
 * \brief Interscept all DNS queries using a firewall divert rule
 *
 * \param[in] add    true if adding divert rule.
 */
static void
divert_dns(bool add)
{
    char cmdline[128];
    sprintf(cmdline, "ipfw -q %s %d divert %d udp from any to any 53 out",
            (add) ? "add" : "delete", ipfw_rule_num, divert_port_num);

    int rc = system(cmdline);
    if (rc < 0) {
        perror("system");
        exit(-1);
    }
}


/**
 * \brief Display simple usage instructions
 *
 * \retval -1 for returning from main()
 */
static int
usage(void)
{
    printf("DNSFilter [-v] [-d <divert port num>] [-r <ipfw rule num>] <blacklist file> [blacklist file...]\n");
    return -1;
}


/**
 * \brief The start of everything.
 */
int
main(int argc, char * const argv[])
{
    /* process command line arguments */
    int ch;
    while ((ch = getopt(argc, argv, "vd:r:")) != -1) {
        switch (ch) {
            case 'v':
                verbose = true;
                break;
            case 'd':
                divert_port_num = atoi(optarg);
                break;
            case 'r':
                ipfw_rule_num = atoi(optarg);
                break;
            case '?':
            default:
                return usage();
        }
    }
    argc -= optind;
    argv += optind;

    /* load blacklist files */
    while (argc > 0) {
        load_blacklist(argv[0]);
        argc--;
        argv++;
    }

    /* if no rules loaded, then just display usage */
    if (!bl || !bl->sl_cur)
        return usage();

    /* add SIGINT (^C) and SIGTERM handler so that we cleanup correctly */
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sa.sa_flags = 0;
    sa.sa_mask = 0;
    int rc = sigaction(SIGINT, &sa, NULL);
    if (rc >= 0)
        rc = sigaction(SIGTERM, &sa, NULL);
    if (rc < 0) {
        perror("sigaction");
        exit(-1);
    }

    /* open DIVERT socket */
    int ds = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT);
    if (ds < 0) {
        if (errno == EACCES) {
            fprintf(stderr, "error: must be executed with superuser rights\n");
        } else {
            perror("socket");
        }
        exit(-1);
    }

    /* bind to DIVERT socket port */
    struct sockaddr_in saddr;
    memset(&saddr, 0x00, sizeof(saddr));
    saddr.sin_family = PF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr.sin_port = htons(divert_port_num);
    rc = bind(ds, (struct sockaddr *)&saddr, sizeof saddr);
    if (rc < 0) {
        perror("bind");
        close(ds);
        exit(-1);
    }

    /* interscept all DNS queries */
    divert_dns(true);

    /* flush any existing DNS results from the local caches */
    rc = system("dscacheutil -flushcache");
    if (rc < 0) {
        perror("system(\"dscacheutil -flushcache\")");
        go = false;
    }

    if (verbose)
        printf("Filtering DNS requests ...\n");

    while (go) {
        /* buffer to hold raw IP packet */
        unsigned char pbuf[1518];

        /* wait for the next DNS packet */
        memset(&saddr, 0x00, sizeof saddr);
        socklen_t saddr_len = sizeof saddr;
        ssize_t ps = recvfrom(ds, pbuf, sizeof(pbuf), 0, (struct sockaddr *)&saddr, &saddr_len);
        if (ps < 0) {
            if (go)
                perror("recv");
            break;
        }

        /* process it */
        process_ip(pbuf, (int)ps);

        /* send onwards packet */
        ps = sendto(ds, pbuf, ps, 0, (struct sockaddr *)&saddr, sizeof saddr);
        if (ps < 0) {
            perror("send");
            break;
        }

    }

    /* remove DNS packet interception */
    divert_dns(false);
    close(ds);

    if (verbose)
        printf("That's all folks\n");
    return 0;
}
