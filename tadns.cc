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
#include "tadns_common.h"

#define MIN_TTL_TIME            60  /* Minimum TTL time (secs)   */
#define MAX_CACHE_ENTRIES   (1<<16) /* Dont cache more than that */
#define CACHE_PURGE_STEP    (1<<14) /* Dont cache more than that */

/*
 * User query. Holds mapping from application-level ID to DNS transaction id,
 * and user defined callback function.
 */
class Query {
public:
    Query() : niter(0), callback(NULL), deps_on(0) {}
    ~Query() {
        // Remove the entry from the parent deps list
        assert(!deps_on || deps_on->deps.count(this));
        if (deps_on)
            deps_on->deps.erase(this);

        for (auto e: deps)
            delete e;
    }

    time_t atimeout;         /* Activity timeout for the query */
    unsigned niter;          /* Number of iterations to resolve this */
    uint16_t qtype;          /* Query type */
    std::string name;        /* Host name */
    void *ctx;               /* Application context */
    dns_callback_t callback; /* User callback routine */
    std::set<Query*> deps;   /* Dependant queries */
    Query* deps_on;          /* Query we wait on */
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
    DNSResolver(std::list<struct sockaddr_storage> serverbundle, unsigned atimeout)
      : pkts_dns_servers(0), pkts_auth_servers(0), dns_servers(serverbundle), atimeout(atimeout) {
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
    void queue(unsigned niter, std::string name, Query *dep, enum dns_record_type qtype, struct sockaddr * dnss);
    Query *createQuery(unsigned niter, void *ctx, std::string name, enum dns_record_type qtype, dns_callback_t callback);
    std::string getNSipaddr(unsigned niter, std::vector<struct dns_record> recs, std::string dom,
            void *ctx, std::string name, enum dns_record_type qtype, dns_callback_t callback);
    void resolveInt(unsigned niter, void *context, std::string host, enum dns_record_type type, dns_callback_t callback);
    void call_user_rec(Query *q, enum dns_error err);

    Query * find_active_query(uint16_t tid) const { return active.count(tid) ? active.at(tid) : NULL; }
    uint16_t getNewTid();

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
    /* Timeouts */
    unsigned atimeout;
};

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

DNSResolverIface * createResolver(const char **dns_servers, unsigned atimeout) {
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

    DNSResolver *dns = new DNSResolver(serverbundle, atimeout);

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
            assert(active.size() == ongoing.size());
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

void DNSResolver::parse_udp(const unsigned char *pkt, int len) {
    Query *q;
    struct header *header = (struct header *) pkt;

    /* Return if we did not send that query */
    if ((q = find_active_query(ntohs(header->tid))) == NULL)
        return;

    /* Actually parse the packet */
    auto dnsp = parse_udp_packet(pkt, len);

    std::vector< std::tuple<unsigned, void*, std::string, enum dns_record_type, dns_callback_t> > deferred;
    if (ntohs(header->nqueries) != 1)
        /* We sent 1 query. We want to see more that 1 answer. */
        call_user_rec(q, DNS_ERROR);
    else if ((header->nanswers | header->nauth | header->nother) == 0)
        /* Received 0 answers */
        call_user_rec(q, DNS_DOES_NOT_EXIST);
    else if (dnsp.questions.size() == 0 || dnsp.questions[0].name != q->name)
        /* Check whether the query matches at all! */
        call_user_rec(q, DNS_ERROR);
    else {
        struct cache_entry entry;
        entry.hits = 0;
        entry.expire = std::numeric_limits<time_t>::max();
        entry.replies = dnsp.answers;

        for (const auto &e: dnsp.answers)
            entry.expire = std::min(time(NULL) + (time_t)e.ttl, entry.expire);

        // Detected some 0 TTL answers, that's an issue cause we rely on the cache as an intermediate
        // structure. That works as long as ttls are significantly bigger than DNS response latency
        entry.expire = std::max(time(NULL) + MIN_TTL_TIME, entry.expire);

        // Insert finding in the cache
        auto cacheentry = std::make_pair(q->name, q->qtype);
        cached.erase(cacheentry);
        auto res = cached.emplace(cacheentry, entry);

        /* If query has a dependant, do not notify the user but re-schedule it */
        if (q->deps.size())
            for (auto de: q->deps)
                deferred.push_back(std::make_tuple(q->niter, de->ctx, de->name, (enum dns_record_type)de->qtype, de->callback));
        else
            call_user(this, q->name, q->qtype, &res.first->second, q->callback, q->ctx, DNS_OK);
    }

    // Delete from active queries and cleanup
    active.erase(dnsp.header.tid);
    ongoing.erase(std::make_pair(q->name, q->qtype));
    assert(active.size() == ongoing.size());

    // Remove the query from the deps list
    delete q;

    // Retry deferred queries
    for (auto df: deferred)
        resolveInt(std::get<0>(df), std::get<1>(df), std::get<2>(df), std::get<3>(df), std::get<4>(df));

    purgeCache();
}

void DNSResolver::call_user_rec(Query *q, enum dns_error err) {
    // If this query has dependencies don't report it
    for (auto de: q->deps)
        call_user_rec(de, err);

    call_user(this, q->name, q->qtype, NULL, q->callback, q->ctx, err);
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
        if (ita->second->atimeout < now) {
            call_user_rec(ita->second, DNS_TIMEOUT);

            ongoing.erase(std::make_pair(ita->second->name, ita->second->qtype));
            delete ita->second;
            ita = active.erase(ita);
            assert(active.size() == ongoing.size());
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
    int totry = -1;
    //for (const auto & e: nsrecs) {
    for (unsigned i = 0; i < nsrecs.size(); i++) {
        struct cache_entry *nsentry = find_cached_query(DNS_A_RECORD, nsrecs[i]);
        if (nsentry != NULL) {
            // Get any valid IP address (random)
            for (const auto & aent: nsentry->replies)
                if (aent.name == nsrecs[i] && aent.rtype == DNS_A_RECORD)
                    ipaddrs.push_back(aent.addr);
        }
        else
            totry = i;
    }
    // Pick a random one if any, a bit biased here
    if (ipaddrs.size())
        return ipaddrs[std::rand() % ipaddrs.size()];

    // Now, packet was useless, cache too, issue a request for ips
    // Prefetch all of them for better balancing and stuff
    #ifdef DO_DNS_PREFETCH
    for (const auto & e: nsrecs)
        this->queue(niter, e, NULL, DNS_A_RECORD, NULL);
    #endif

    if (totry >= 0) {
        Query * oq = createQuery(niter, ctx, name, qtype, callback);
        this->queue(niter, nsrecs[totry], oq, DNS_A_RECORD, NULL);
        return "";
    }
    else {
        // None of the NS servers are really up for this!
        call_user(this, name, qtype, NULL, callback, ctx, DNS_DOES_NOT_EXIST);
    }
    return "";
}

void DNSResolver::resolve(void *ctx, std::string name,
                          enum dns_record_type qtype, dns_callback_t callback) {
    this->resolveInt(0, ctx, name, qtype, callback);
}

void DNSResolver::resolveInt(unsigned niter, void *ctx, std::string name,
                          enum dns_record_type qtype, dns_callback_t callback) {

    std::transform(name.begin(), name.end(), name.begin(), ::tolower);

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
            // We don't have the NS for that record, ask for it (cache miss)
            Query * oq = createQuery(niter, ctx, name, qtype, callback);
            this->queue(niter, part, oq, iqtype, dnss);
            return; // Will come back here eventually :D
        }

        level++;
    }
}

Query * DNSResolver::createQuery(unsigned niter, void *ctx, std::string name,
                    enum dns_record_type qtype, dns_callback_t callback) {

    std::transform(name.begin(), name.end(), name.begin(), ::tolower);

    time_t now = time(NULL);
    Query * query = new Query();
    query->ctx = ctx;
    query->qtype = (uint16_t) qtype;
    query->callback = callback;
    query->atimeout = now + this->atimeout;
    query->niter = niter + 1;
    query->name = name;

    return query;
}

uint16_t DNSResolver::getNewTid() {
    while(1) {
        uint16_t n = ++tidseq;
        if (active.count(n) == 0)
            return n;
        std::cout << "Dup!" << std::endl;
    }
}

// Precondition, a query with dep!=0 cannot have a cache hit (check before queuing)
void DNSResolver::queue(unsigned niter, std::string name, Query *dep, enum dns_record_type qtype, struct sockaddr * dnss) {
    struct cache_entry * centry;
    struct dns_cb_data cbd;

    std::transform(name.begin(), name.end(), name.begin(), ::tolower);

    /* Search the cache first */
    if ((centry = find_cached_query(qtype, name)) != NULL) {
        assert(dep == NULL);

        centry->hits++;
        return;
    }

    /* Check ongoing requests */
    // Dependants get merged and will be waken all together
    // if there is no callback to the user, safe to ignore it
    auto lookup = std::make_pair(name, qtype);
    auto existingq = ongoing.find(lookup);
    if (existingq != ongoing.end()) {
        if (dep) {
            existingq->second->deps.insert(dep);
            dep->deps_on = existingq->second;
        }
        return;
    }

    /* Allocate new query */
    Query * query = createQuery(niter, NULL, name, qtype, NULL);
    if (dep) {
        query->deps.insert(dep);
        dep->deps_on = query;
    }

    struct dns_packet outp;

    /* Prepare DNS packet header */
    outp.header.tid      = getNewTid();
    outp.header.flags    = 0x100;        /* Haha. guess what it is */
    outp.header.nqueries = 1;            /* Just one query */
    outp.header.nanswers = 0;
    outp.header.nauth    = 0;
    outp.header.nother   = 0;

    struct dns_question q;
    q.qtype = qtype;
    q.qclass = 0x0001;
    q.name = name;
    outp.questions.push_back(q);

    uint8_t pkt[DNS_PACKET_LEN];
    unsigned psize = serialize_udp_packet(&outp, pkt);
    assert(psize < sizeof(pkt));

    /* FIXME Add some queueing mechanism for packets? */
    if (dnss)
        pkts_auth_servers++;
    else
        pkts_dns_servers++;

    /* Pick a server to send query to */
    struct sockaddr * serv = dnss ? dnss : getNextServer();
    int ssock = serv->sa_family == AF_INET ? sock4 : sock6;
    int addrl = serv->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    if (sendto(ssock, pkt, psize, 0, serv, addrl) != psize) {
        Query * reportq = dep ? dep : query;
        call_user(this, reportq->name, reportq->qtype, NULL, reportq->callback, reportq->ctx, DNS_ERROR);
        delete query;
    } else {
        active.emplace(outp.header.tid, query);
        ongoing[lookup] = query;
        assert(active.size() == ongoing.size());
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
std::set<std::string> stillrunning;

static void callback(struct dns_cb_data *cbd) {
    inflight--;
    stillrunning.erase(cbd->name);

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
    if ((dns = createResolver(NULL, 10)) == NULL) {
        (void) fprintf(stderr, "failed to init resolver\n");
        exit(EXIT_FAILURE);
    }

    /* Select on resolver socket */
    do {
        while (*domains != 0 && inflight < 100) {
            stillrunning.insert(*domains);
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

    assert(stillrunning.size() == 0);

    delete dns;

    return (EXIT_SUCCESS);
}
#endif /* ADIG */
