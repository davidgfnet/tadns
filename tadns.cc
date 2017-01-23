/*
 * Copyright (c) 2004-2005 Sergey Lyubka <valenok@gmail.com>
 * Copyright (c) 2017 David Guillen Fandos <david@davidgf.net>
 *
 * "THE BEER-WARE LICENSE" (Revision 42):
 * Sergey Lyubka wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <set>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <list>
#include <string>
#include <limits>
#include <arpa/inet.h>
#include <iostream>

#ifdef _WIN32
#pragma comment(lib,"ws2_32")
#pragma comment(lib,"advapi32")
#include <winsock.h>
typedef int socklen_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
#else
#define closesocket(x) close(x)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <unistd.h>
#endif /* _WIN32 */

#include "tadns.h"

#define DNS_MAX             1025    /* Maximum host name          */
#define DNS_PACKET_LEN      2048    /* Buffer size for DNS packet */
#define MAX_CACHE_ENTRIES   (1<<14) /* Dont cache more than that  */
#define CACHE_PURGE_STEP    (1<<12) /* Dont cache more than that  */

static int nonblock(int fd);

/*
 * User query. Holds mapping from application-level ID to DNS transaction id,
 * and user defined callback function.
 */
class Query {
public:
    Query() : niter(0), callback(NULL) {}
    ~Query() {
        for (auto e: deps)
            delete e;
    }

    time_t timeout;          /* Time when this query timeout */
    unsigned niter;          /* Number of iterations to resolve this */
    uint16_t qtype;          /* Query type */
    char name[DNS_MAX];      /* Host name */
    void *ctx;               /* Application context */
    dns_callback_t callback; /* User callback routine */
    std::vector<Query*> deps;/* Dependant query */
};

struct cache_entry {
    std::vector<struct dns_record> replies;
    time_t expire;
    unsigned hits;
};

/*
 * Resolver descriptor.
 */
class DNSResolver : public DNSResolverIface {
public:
    DNSResolver(std::list<struct sockaddr_storage> serverbundle)
      : pkts_dns_servers(0), pkts_auth_servers(0), dns_servers(serverbundle) {
        this->sock4 = socket(PF_INET,  SOCK_DGRAM, 17);
        this->sock6 = socket(PF_INET6, SOCK_DGRAM, 17);
        /* Make it non blocking */
        nonblock(sock4);
        nonblock(sock6);
        /* Increase socket's receive buffer */
        int rcvbufsiz = 128 * 1024;
        (void) setsockopt(sock4, SOL_SOCKET, SO_RCVBUF,
            (char *) &rcvbufsiz, sizeof(rcvbufsiz));
        (void) setsockopt(sock6, SOL_SOCKET, SO_RCVBUF,
            (char *) &rcvbufsiz, sizeof(rcvbufsiz));
        tidseq = 0;
        active.rehash(MAX_CACHE_ENTRIES*2);
    }

    ~DNSResolver() {
        if (sock4 != -1)
            (void) closesocket(sock4);
        if (sock6 != -1)
            (void) closesocket(sock6);

        for (auto it: active)
            delete it.second;
    }

    std::pair<int,int> getFds() const { return std::make_pair(sock4, sock6); }
    void resolve(void *context, std::string host, enum dns_record_type type, dns_callback_t callback) override;
    void cancel(const void *context) override;
    int poll() override;
    unsigned ongoingReqs() override { return active.size(); }

protected:
    cache_entry* find_cached_query(enum dns_record_type qtype, std::string name);
    void parse_udp(const unsigned char *pkt, int len);
    void purgeCache();
    struct sockaddr *getNextServer();
    void queue(unsigned niter, void *ctx, const char *name, Query *dep, enum dns_record_type qtype,
               dns_callback_t callback, struct sockaddr * dnss);
    Query *createQuery(unsigned niter, void *ctx, const char *name, enum dns_record_type qtype, dns_callback_t callback);
    const uint8_t* parse_answer(const uint8_t *pkt, int len, const uint8_t *p,
                                unsigned count, std::vector<struct dns_record> &r, enum dns_response_type resp);
    std::string getNSipaddr(unsigned niter, std::vector<struct dns_record> recs, std::string dom,
            void *ctx, std::string name, enum dns_record_type qtype, dns_callback_t callback);
    void resolveInt(unsigned niter, void *context, std::string host, enum dns_record_type type, dns_callback_t callback);

    Query * find_active_query(uint16_t tid) const { return active.count(tid) ? active.at(tid) : NULL; }

    /* UDP sockets used for queries */
    int sock4, sock6;
    uint16_t tidseq; /* Latest tid used */
    uint32_t pkts_dns_servers, pkts_auth_servers;

    /* Available DNS servers */
    std::list<struct sockaddr_storage> dns_servers;
    /* Active queries */
    std::unordered_map<uint16_t, Query*> active;
    std::map< std::pair<std::string, uint16_t>, Query*> ongoing;
    /* Cached queries */
    std::map< std::pair<std::string, uint16_t>, cache_entry> cached; 
};

/*
 * DNS network packet
 */
struct header {
    uint16_t tid;       /* Transaction ID        */
    uint16_t flags;     /* Flags            */
    uint16_t nqueries;  /* Questions            */
    uint16_t nanswers;  /* Answers            */
    uint16_t nauth;     /* Authority PRs        */
    uint16_t nother;    /* Other PRs            */
    uint8_t  data[];    /* Data, variable length    */
};

/*
 * Fetch name from DNS packet
 */
static unsigned fetch(const uint8_t *pkt, const uint8_t *s, int pktsiz, char *dst, int dstlen) {
    const uint8_t *e = pkt + pktsiz;
    unsigned skip = 0;
    bool labelj = false;
    int j, i = 0, n = 0;

    while (*s != 0 && s < e) {
        if (n > 0)
            dst[i++] = '.';

        if (i >= dstlen)
            break;

        if (((n = *s++) & 0xc0) == 0xc0) {
            s = pkt + (((n&3) << 8) | *s);    /* New offset */
            n = 0;
            if (!labelj)
                skip += 2;
            labelj = true;
        } else {
            if (!labelj)
                skip += std::min(n, dstlen - i) + 1;
            for (j = 0; j < n && i < dstlen; j++)
                dst[i++] = *s++;
        }
    }

    dst[i] = '\0';
    return skip + (labelj ? 0 : 1);
}

/*
 * Put given file descriptor in non-blocking mode. return 0 if success, or -1
 */
static int nonblock(int fd) {
#ifdef    _WIN32
    unsigned long on = 1;
    return (ioctlsocket(fd, FIONBIO, &on));
#else
    int flags;
    flags = fcntl(fd, F_GETFL, 0);
    return (fcntl(fd, F_SETFL, flags | O_NONBLOCK));
#endif /* _WIN32 */
}

bool parseAddr(const char *ipaddr, struct sockaddr_storage *addrout) {
    unsigned ok = 0;
    union {
        struct sockaddr_storage addrst;
        struct sockaddr_in6 ipv6addr;
        struct sockaddr_in ipv4addr;
    } addrunion;
    if (strchr(ipaddr, '.') == NULL) {
        addrunion.ipv6addr.sin6_family = AF_INET6;
        addrunion.ipv6addr.sin6_port = htons(53);
        addrunion.ipv6addr.sin6_flowinfo = 0;
        addrunion.ipv6addr.sin6_scope_id = 0;
        ok |= inet_pton(AF_INET6, ipaddr, &addrunion.ipv6addr.sin6_addr);
    } else {
        addrunion.ipv4addr.sin_family = AF_INET;
        addrunion.ipv4addr.sin_port = htons(53);
        ok |= inet_pton(AF_INET, ipaddr, &addrunion.ipv4addr.sin_addr);
    }
    *addrout = addrunion.addrst;
    return (ok == 1);
}

/*
 * Find what DNS server to use. Return 0 if OK, -1 if error
 */
#ifndef TADNS_DONT_USE_OS_DNS_SERVERS
static std::list<struct sockaddr_storage> getdnsip() {
    std::list<struct sockaddr_storage> ret;

#ifdef _WIN32
    LONG err;
    HKEY hKey, hSub;
    char subkey[512], dhcpns[512], ns[512], value[128], *key =
    "SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces";

    if ((err = RegOpenKey(HKEY_LOCAL_MACHINE,
        key, &hKey)) != ERROR_SUCCESS) {
        fprintf(stderr, "cannot open reg key %s: %d\n", key, err);
        return ret;
    } else {
        for (int i = 0; RegEnumKey(hKey, i, subkey,
            sizeof(subkey)) == ERROR_SUCCESS; i++) {
            DWORD type, len = sizeof(value);
            if (RegOpenKey(hKey, subkey, &hSub) == ERROR_SUCCESS &&
                (RegQueryValueEx(hSub, "NameServer", 0,
                &type, value, &len) == ERROR_SUCCESS ||
                RegQueryValueEx(hSub, "DhcpNameServer", 0,
                &type, value, &len) == ERROR_SUCCESS)) {

                struct sockaddr_storage addr;
                if (parseAddr(value, &addr))
                    ret.push_back(addr);
                RegCloseKey(hSub);
            }
        }
        RegCloseKey(hKey);
    }
#else
    FILE *fp;
    char line[512];
    char ipaddr[512];

    if ((fp = fopen("/etc/resolv.conf", "r")) != NULL) {
        /* Try to figure out what DNS server to use */
        while (fgets(line, sizeof(line), fp) != NULL) {
            if (sscanf(line, "nameserver%*[ \t]%s", ipaddr) == 1) {
                struct sockaddr_storage addr;
                if (parseAddr(ipaddr, &addr))
                    ret.push_back(addr);
            }
        }
        (void) fclose(fp);
    }
#endif /* _WIN32 */

    return (ret);
}
#endif

DNSResolverIface * createResolver(const char **dns_servers) {
#ifdef _WIN32
    { WSADATA data; WSAStartup(MAKEWORD(2,2), &data); }
#endif /* _WIN32 */

    std::list<struct sockaddr_storage> serverbundle;

    if (!dns_servers) {
        #ifdef TADNS_DONT_USE_OS_DNS_SERVERS
            return (NULL);
        #else
        serverbundle = getdnsip();
        if (!serverbundle.size())
            return (NULL);
        #endif
    }
    else {
        while (*dns_servers != NULL) {
            struct sockaddr_storage addr;
            if (parseAddr(*dns_servers++, &addr))
                serverbundle.push_back(addr);
        }
    }

    DNSResolver *dns = new DNSResolver(serverbundle);

    return (dns);
}

struct sockaddr *DNSResolver::getNextServer() {
    dns_servers.push_back(*dns_servers.begin());
    dns_servers.pop_front();
    return (struct sockaddr*)&(*dns_servers.begin());
}

// Guaranteed that lookup won't update the cache in anyway, so ptrs to
// cache_entries are valid until purgeCache is called
cache_entry* DNSResolver::find_cached_query(enum dns_record_type qtype, std::string name) {
    time_t now = time(NULL);
    auto entry = std::make_pair(name, qtype);
    if (cached.find(entry) != cached.end()) {
        auto r = &(cached.at(entry));
        if (r->expire > now)
            return r;
    }
    return (NULL);
}

/*
 * User wants to cancel query
 */
void DNSResolver::cancel(const void *context) {
    for (auto it: active) {
        if (it.second->ctx == context) {
            ongoing.erase(std::make_pair(it.second->name, it.second->qtype));
            delete it.second;
            active.erase(it.first);
            return;
        }
    }
}

static void
call_user(DNSResolver *dns, std::string name, uint16_t qtype, 
          const struct cache_entry *entry, dns_callback_t cb, void *ctx, enum dns_error error)
{
    struct dns_cb_data cbd;
    cbd.context = ctx;
    cbd.query_type = (enum dns_record_type) qtype;
    cbd.error = error;
    cbd.name = name;

    if (entry)
        cbd.replies = entry->replies;

    if (cb)
        cb(&cbd);
}

void DNSResolver::purgeCache() {
    time_t now = time(NULL);
    std::map<unsigned, std::pair<std::string, uint16_t> > sortedcache;

    if (sortedcache.size() > MAX_CACHE_ENTRIES) {
        /* Cleanup cached queries */
        auto itc = cached.begin();
        while (itc != cached.end()) {
            if (itc->second.expire < now)
                itc = cached.erase(itc);
            else {
                sortedcache.emplace(itc->second.hits, itc->first);
                itc++;
            }
        }

        while (sortedcache.size() > MAX_CACHE_ENTRIES - CACHE_PURGE_STEP) {
            cached.erase(sortedcache.begin()->second);
            sortedcache.erase(sortedcache.begin());
        }
    }
}

const uint8_t* DNSResolver::parse_answer(const uint8_t *pkt, int len, const uint8_t *p,
                                         unsigned count, std::vector<struct dns_record> &r, enum dns_response_type respt) {
    const uint8_t *e = pkt + len;
    char name[1025];

    /* Loop through the answers, we want A type answer */
    for (unsigned a = 0; a < count && &p[12] < e; a++) {
        /* Get answer NAME, make sure it matches! */
        p += fetch(pkt, p, len, name, sizeof(name) - 1);

        uint16_t type = ntohs(((uint16_t *)p)[0]);
        uint32_t ttl = ntohl(((uint32_t *)p)[1]);
        uint16_t dlen = ntohs(((uint16_t *)p)[4]);

        p += 10;

        struct dns_record rec;
        rec.rtype = (enum dns_record_type)type;
        rec.ttl = ttl;
        rec.name = std::string(name);
        rec.resptype = respt;

        std::transform(rec.name.begin(), rec.name.end(), rec.name.begin(), ::tolower);

        if (type == DNS_MX_RECORD ||
            type == DNS_NS_RECORD ||
            type == DNS_CNAME_RECORD) {

            fetch(pkt, p, len, name, sizeof(name) - 1);
            rec.addr = std::string(name);

            std::transform(rec.addr.begin(), rec.addr.end(), rec.addr.begin(), ::tolower);
        } else {
            if (dlen > e-p && e > p)
                dlen = e-p;
            rec.addr = std::string((char*)p, dlen);
        }
        r.push_back(rec);

        p += dlen;
    }

    return p;
}

void DNSResolver::parse_udp(const unsigned char *pkt, int len) {
    struct header *header;
    const unsigned char *p, *e;
    Query *q;
    int nlen;

    /* We sent 1 query. We want to see more that 1 answer. */
    header = (struct header *) pkt;
    if (ntohs(header->nqueries) != 1)
        return;

    /* Return if we did not send that query */
    if ((q = find_active_query(header->tid)) == NULL)
        return;

    /* Received 0 answers */
    if ((header->nanswers | header->nauth | header->nother) == 0) {
        call_user(this, q->name, q->qtype, NULL, q->callback, q->ctx, DNS_DOES_NOT_EXIST);
        return;
    }

    /* Skip host name */
    for (e = pkt + len, nlen = 0, p = &header->data[0];
        p < e && *p != '\0'; p++)
        nlen++;

    /* We sent query class 1, query type A/MX */
    if (&p[5] > e || ntohs(*(uint16_t*)(p + 1)) != q->qtype)
        return;

    /* Go to the first answer section */
    p += 5;

    struct cache_entry entry;
    entry.hits = 0;
    entry.expire = std::numeric_limits<time_t>::max();

    p = parse_answer(pkt, len, p, ntohs(header->nanswers), entry.replies, RESPONSE_ANSWER);
    p = parse_answer(pkt, len, p, ntohs(header->nauth), entry.replies, RESPONSE_AUTHORITATIVE);
    p = parse_answer(pkt, len, p, ntohs(header->nother), entry.replies, RESPONSE_ADDITIONAL);

    for (const auto &e: entry.replies)
        entry.expire = std::min(time(NULL) + (time_t)e.ttl, entry.expire);

    // Insert finding in the cache
    cached.erase(std::make_pair(q->name, q->qtype));
    auto res = cached.emplace(std::make_pair(q->name, q->qtype), entry);

    /* If query has a dependant, do not notify the user but re-schedule it */
    if (q->deps.size())
        for (auto de: q->deps)
            resolveInt(q->niter, de->ctx, de->name, (enum dns_record_type)de->qtype, de->callback);
    else
        call_user(this, q->name, q->qtype, &res.first->second, q->callback, q->ctx, DNS_OK);

    // Delete from active queries and cleanup
    active.erase(header->tid);
    ongoing.erase(std::make_pair(q->name, q->qtype));
    delete q;

    purgeCache();
}

int DNSResolver::poll() {
    struct sockaddr_in sa;
    socklen_t len = sizeof(sa);
    int n, num_packets = 0;
    unsigned char pkt[DNS_PACKET_LEN];
    time_t now;

    now = time(NULL);

    /* Check our sockets for new stuff */
    while ((n = recvfrom(sock4, pkt, sizeof(pkt), 0,
        (struct sockaddr *) &sa, &len)) > 0 &&
        n > (int) sizeof(struct header)) {
        this->parse_udp(pkt, n);
        num_packets++;
    }
    while ((n = recvfrom(sock6, pkt, sizeof(pkt), 0,
        (struct sockaddr *) &sa, &len)) > 0 &&
        n > (int) sizeof(struct header)) {
        this->parse_udp(pkt, n);
        num_packets++;
    }

    /* Cleanup expired active queries */
    auto ita = active.begin();
    while (ita != active.end()) {
        if (ita->second->timeout < now) {
            /* Report the original query if exists */
            if (ita->second->deps.size())
                for (auto de: ita->second->deps)
                    call_user(this, de->name, de->qtype, NULL,
                              de->callback, de->ctx, DNS_TIMEOUT);
            else
                call_user(this, ita->second->name, ita->second->qtype, NULL,
                          ita->second->callback, ita->second->ctx, DNS_TIMEOUT);

            ongoing.erase(std::make_pair(ita->second->name, ita->second->qtype));
            delete ita->second;
            ita = active.erase(ita);
        }
        else ita++;
    }

    return (num_packets);
}

std::pair<std::string, bool> tokenizedom (std::string dom, unsigned level) {
    std::vector<std::string> chunks;
    while (dom.size()) {
        auto p = dom.find(".");
        if (p != std::string::npos) {
            chunks.push_back(dom.substr(0, p));
            dom = dom.substr(p+1);
        }
        else {
            chunks.push_back(dom);
            break;
        }
    }

    bool lastquery = level > chunks.size();
    std::string ret;
    while (level-- && chunks.size()) {
        ret = chunks.back() + "." + ret;
        chunks.pop_back();
    }
    if (ret.size())
        ret.pop_back();

    return std::make_pair(ret, lastquery);
}

// Given a response to NS query, get an A ip that points to them
// Can return an IP, an error (cannot recover) or try again later
std::string
DNSResolver::getNSipaddr(unsigned niter, std::vector<struct dns_record> recs, std::string dom,
                         void *ctx, std::string name,
                         enum dns_record_type qtype, dns_callback_t callback) {

    // Filter all the NS records
    std::vector<std::string> nsrecs;
    std::unordered_map<std::string, std::string> arecs;
    for (const auto & e: recs) {
        if (e.name == dom && e.rtype == DNS_NS_RECORD)
            nsrecs.push_back(e.addr);
        if (e.rtype == DNS_A_RECORD)
            arecs[e.name] = e.addr;
    }

    // If we have no NS servers, it gets a bit more interesting.
    // According to rfc7816 (Qname minimization) we should need to go one level up
    // trying the same server
    if (!nsrecs.size())
        return "-";   // Hack, shame on me

    // Get a random permutation to avoid banging the same server
    std::random_shuffle(nsrecs.begin(), nsrecs.end());

    // Now go and check whether we have the A adress for them (in response)
    for (const auto & e: nsrecs)
        if (arecs.count(e))
            return arecs.at(e);

    // Seems like we don't have it in the packet, check the query cache
    std::vector<std::string> ipaddrs;
    for (const auto & e: nsrecs) {
        struct cache_entry *nsentry = find_cached_query(DNS_A_RECORD, e);
        if (nsentry != NULL) {
            // Get any valid IP address (random)
            for (const auto & aent: nsentry->replies)
                if (aent.name == e && aent.rtype == DNS_A_RECORD)
                    ipaddrs.push_back(aent.addr);
        }
    }
    // Pick a random one if any, a bit biased here
    if (ipaddrs.size())
        return ipaddrs[std::rand() % ipaddrs.size()];

    // Now, packet was useless, cache too, issue a request for ips
    // Prefetch all of them for better balancing and stuff
	#ifdef DO_DNS_PREFETCH
    for (const auto & e: nsrecs)
        this->queue(niter, NULL, e.c_str(), NULL, DNS_A_RECORD, NULL, NULL);
	#endif
    
    Query * oq = createQuery(niter, ctx, name.c_str(), qtype, callback);
    this->queue(niter, NULL, nsrecs[0].c_str(), oq, DNS_A_RECORD, NULL, NULL);

    return "";
}

void DNSResolver::resolve(void *ctx, std::string name,
                          enum dns_record_type qtype, dns_callback_t callback) {
    this->resolveInt(0, ctx, name, qtype, callback);
}

void DNSResolver::resolveInt(unsigned niter, void *ctx, std::string name,
                          enum dns_record_type qtype, dns_callback_t callback) {

    if (niter >= DNS_QUERY_MAXITER) {
        call_user(this, name, qtype, NULL, callback, ctx, DNS_TIMEOUT);
        std::cout << "MAX Reached " << name << std::endl;
        return;
    }

    /* Do recursive solving */
    unsigned level = 0;
    union {
        struct sockaddr_storage addrst;
        struct sockaddr_in6 ipv6addr;
        struct sockaddr_in ipv4addr;
    } addrunion;
    struct sockaddr * dnss = NULL;

    while (1) {
        std::string part; bool lastq;
        std::tie(part, lastq) = tokenizedom(name, level);
        enum dns_record_type iqtype = lastq ? qtype : DNS_NS_RECORD;

        /* Search the cache first */
        struct cache_entry *centry = find_cached_query(iqtype, part);
        if (centry != NULL) {
            centry->hits++;
            
            if (lastq) {
                assert(iqtype == qtype);
                // This is the original request, all set, shoot!
                call_user(this, name, qtype, centry, callback, ctx, DNS_OK);
                return;
            }

            // We get here cause the current "part" has some NS responses
            // Sometimes the NS responses come with the A/AAAA records (optimization!)
            // Also we don't want to always use the same NS server, so round robin it
            std::string ipaddr = getNSipaddr(niter, centry->replies, part, ctx, name, qtype, callback);

            if (!ipaddr.size())
                return;

            if (ipaddr.size() == 4) {
                addrunion.ipv4addr.sin_family = AF_INET;
                addrunion.ipv4addr.sin_port = htons(53);
                memcpy(&addrunion.ipv4addr.sin_addr, ipaddr.c_str(), 4); // FIXME: Check addr sizes

                dnss = (struct sockaddr*)&addrunion;
            }
        } else {
            // We don't have the NS for that record, ask for it
            Query * oq = createQuery(niter, ctx, name.c_str(), qtype, callback);
            this->queue(niter, NULL, part.c_str(), oq, iqtype, NULL, dnss);
            return; // Will come back here eventually :D
        }

        level++;
    }
}

Query * DNSResolver::createQuery(unsigned niter, void *ctx, const char *name, 
                    enum dns_record_type qtype, dns_callback_t callback) {

    time_t now = time(NULL);
    Query * query = new Query();
    query->ctx = ctx;
    query->qtype = (uint16_t) qtype;
    query->callback = callback;
    query->timeout = now + DNS_QUERY_TIMEOUT;
    query->niter = niter + 1;

    char *p;
    for (p = query->name; *name &&
        p < query->name + sizeof(query->name) - 1; name++, p++)
        *p = tolower(*name);
    *p = '\0';

    return query;
}

void DNSResolver::queue(unsigned niter, void *ctx, const char *name, Query *dep,
                        enum dns_record_type qtype, dns_callback_t callback, struct sockaddr * dnss) {
    struct cache_entry * centry;
    struct header    *header;
    int i, n;
    char pkt[DNS_PACKET_LEN], *p;
    const char     *s;
    struct dns_cb_data cbd;

    /* Search the cache first */
    if ((centry = find_cached_query(qtype, name)) != NULL) {
        centry->hits++;
        call_user(this, name, qtype, centry, callback, ctx, DNS_OK);
        if (dep) delete dep;
        return;
    }

    /* Check ongoing requests */
    // Dependants get merged and will be waken all together
    // if there is no callback to the user, safe to ignore it
    auto lookup = std::make_pair(name, qtype);
    if (dep || !callback) {
        auto existingq = ongoing.find(lookup);
        if (existingq != ongoing.end()) {
            if (dep)
                existingq->second->deps.push_back(dep);
            return;
        }
    }

    /* Allocate new query */
    Query * query = createQuery(niter, ctx, name, qtype, callback);
    if (dep)
        query->deps.push_back(dep);
    name = query->name;

    /* Prepare DNS packet header */
    header        = (struct header *) pkt;
    header->tid    = ++tidseq;
    header->flags    = htons(0x100);        /* Haha. guess what it is */
    header->nqueries= htons(1);        /* Just one query */
    header->nanswers= 0;
    header->nauth    = 0;
    header->nother    = 0;

    /* Encode DNS name */
    int name_len = strlen(name);
    bool nempty = name_len != 0;
    p = (char *) &header->data;    /* For encoding host name into packet */

    do {
        if ((s = strchr(name, '.')) == NULL)
            s = name + name_len;

        n = s - name;            /* Chunk length */
        *p++ = n;            /* Copy length */
        for (i = 0; i < n; i++)        /* Copy chunk */
            *p++ = name[i];

        if (*s == '.')
            n++;

        name += n;
        name_len -= n;

    } while (*s != '\0');

    if (nempty)
        *p++ = 0;            /* Mark end of host name */
    *p++ = 0;            /* Well, lets put this byte as well */
    *p++ = (unsigned char) qtype;    /* Query Type */

    *p++ = 0;
    *p++ = 1;            /* Class: inet, 0x0001 */

    assert(p < pkt + sizeof(pkt));
    n = p - pkt;            /* Total packet length */

    /* FIXME Add some queueing mechanism for packets? */
    if (dnss)
        pkts_auth_servers++;
    else
        pkts_dns_servers++;

    /* Pick a server to send query to */
    struct sockaddr * serv = dnss ? dnss : getNextServer();
    int ssock = serv->sa_family == AF_INET ? sock4 : sock6;
    int addrl = serv->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    if (sendto(ssock, pkt, n, 0, serv, addrl) != n) {
        Query * reportq = dep ? dep : query;
        call_user(this, reportq->name, reportq->qtype, NULL, reportq->callback, reportq->ctx, DNS_ERROR);
        delete query;
    } else {
        assert(active.size() == ongoing.size());
        active.emplace(tidseq, query);
        ongoing[lookup] = query;
    }
}

#ifdef ADIG

static void usage(const char *prog) {
    (void) fprintf(stderr,
        "usage: %s [-q-type] <domain> [<domain>]\n"
        " example: %s -a example.com google.com\n", prog, prog);
    exit(EXIT_FAILURE);
}

unsigned inflight = 0;

static void callback(struct dns_cb_data *cbd) {
    inflight--;

    switch (cbd->error) {
    case DNS_OK:
        printf("DNS response for [%s]\n", cbd->name.c_str());
        for (auto rec: cbd->replies) {
            const unsigned char *addr = (unsigned char*)rec.addr.data();
            const unsigned char *name = (unsigned char*)rec.name.data();

            switch (rec.rtype) {
            case DNS_A_RECORD:
                printf("%s A %u.%u.%u.%u\n", name,
                    addr[0], addr[1],
                    addr[2], addr[3]);
                break;
            case DNS_MX_RECORD:
                printf("%s MX %s\n", name, addr);
                break;
            case DNS_CNAME_RECORD:
                printf("%s CNAME %s\n", name, addr);
                break;
            case DNS_NS_RECORD:
                printf("%s NS %s\n", name, addr);
                break;
            default:
                printf("Other Record %s %d\n", name, rec.rtype);
                break;
            }
        }
        break;
    case DNS_TIMEOUT:
        printf("Query timeout for [%s]\n", cbd->name.c_str());
        break;
    case DNS_DOES_NOT_EXIST:
        printf("No such address: [%s]\n", cbd->name.c_str());
        break;
    case DNS_ERROR:
        printf("System error occured\n");
        break;
    }
}

int main(int argc, char *argv[]) {
    const char *prog = argv[0];
    enum dns_record_type qtype = DNS_A_RECORD;

    if (argc == 1)
        usage(prog);

    char ** domains = argv[1][0] == '-' ? &argv[2] : &argv[1];
    if (argc > 2) {
        if (!strcmp(argv[1], "-mx"))
            qtype = DNS_MX_RECORD;
        else if (!strcmp(argv[1], "-a"))
            qtype = DNS_A_RECORD;
        else if (!strcmp(argv[1], "-aaaa"))
            qtype = DNS_AAAA_RECORD;
    }

    DNSResolverIface *dns;
    if ((dns = createResolver(NULL)) == NULL) {
        (void) fprintf(stderr, "failed to init resolver\n");
        exit(EXIT_FAILURE);
    }

    /* Select on resolver socket */
    do {
        while (*domains != 0 && inflight < 100) {
            dns->resolve(NULL, *domains++, qtype, callback);
            inflight++;
        }

        fd_set set;
        struct timeval tv = {1, 0};
        auto sockets = dns->getFds();
        FD_ZERO(&set);
        FD_SET(sockets.first, &set);
        FD_SET(sockets.second, &set);
        select(std::max(sockets.first, sockets.second) + 1, &set, NULL, NULL, &tv);

        dns->poll();
    } while (dns->ongoingReqs() || *domains != 0);

    delete dns;

    return (EXIT_SUCCESS);
}
#endif /* ADIG */
