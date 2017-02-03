/*
 * Copyright (c) 2004-2005 Sergey Lyubka <valenok@gmail.com>
 * Copyright (c) 2017 David Guillen Fandos <david@davidgf.net>
 *
 * "THE BEER-WARE LICENSE" (Revision 42):
 * Sergey Lyubka wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 */

/*
 * Simple asynchronous DNS resolver.
 * Can resolve A records (IP addresses for a given name),
 * and MX records (IP addresses of mail exchanges for a given domain).
 * It holds resolved IP addresses in a cache.
 *
 * Can be used as a library, and be compiled into C/C++ program.
 * Can be compiled as stand-alone program similar to `dig' utility.
 *
 * Compilation:
 *    cc -DADIG dns.c        (UNIX)
 *    cl dns.c /DADIG        (Windows, MSVS)
 */

#ifndef DNS_HEADER_INCLUDED
#define DNS_HEADER_INCLUDED

#include <vector>
#include <string>

enum dns_record_type {
    DNS_A_RECORD = 0x01,      /* Lookup IP adress for host */
    DNS_NS_RECORD = 0x02,     /* Nameserver look           */
    DNS_CNAME_RECORD = 0x05,  /* Nameserver look           */
    DNS_AAAA_RECORD = 0x1C,
    DNS_MX_RECORD = 0x0f      /* Lookup MX for domain      */
};

enum dns_response_type {
    RESPONSE_ANSWER,
    RESPONSE_AUTHORITATIVE,
    RESPONSE_ADDITIONAL,
    RESPONSE_LAST
};

/*
 * User defined function that will be called when DNS reply arrives for
 * requested hostname. "struct dns_cb_data" is passed to the user callback,
 * which has an error indicator, resolved address, etc.
 */

enum dns_error {
    DNS_OK,             /* No error                     */
    DNS_DOES_NOT_EXIST, /* Error: adress does not exist */
    DNS_TIMEOUT,        /* Lookup time expired          */
    DNS_ERROR           /* No memory or other error     */
};

struct dns_record {
    enum dns_record_type rtype;
    enum dns_response_type resptype;
    std::string name, addr;
    uint32_t ttl;
};

struct dns_cb_data {
    void *context;
    enum dns_error error;
    enum dns_record_type query_type;
    std::string name; // Requested host name
    std::vector<struct dns_record> replies;
};

typedef void (*dns_callback_t)(struct dns_cb_data *);

#define    DNS_QUERY_MAXITER   16   /* Query max iterations */

//#define DO_DNS_PREFETCH              /* Do prefetch when more than one server is available */

//#define TADNS_DONT_USE_OS_DNS_SERVERS  /* Use OS's DNS servers facilities */

/*
 * The API. Only support for IPv4 so far
 */

class DNSResolverIface {
public:
    virtual ~DNSResolverIface() {}

    virtual std::pair<int,int> getFds() const = 0;
    virtual void resolve(void *context, std::string host, enum dns_record_type type, dns_callback_t callback) = 0;
    virtual void cancel(const void *context) = 0;
    virtual int poll() = 0;
    virtual unsigned ongoingReqs() = 0;
};

extern class DNSResolverIface *createResolver(const char **dns_servers, unsigned atimeout);

#endif /* DNS_HEADER_INCLUDED */
