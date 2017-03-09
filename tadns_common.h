
#ifndef TADNS_COMMON____H_
#define TADNS_COMMON____H_

#define DNS_PACKET_LEN      2048    /* Buffer size for DNS packet */

#include "tadns.h"

/*
 * DNS network packet
 */
struct header {
    uint16_t tid;       /* Transaction ID        */
    uint16_t flags;     /* Flags                 */
    uint16_t nqueries;  /* Questions             */
    uint16_t nanswers;  /* Answers               */
    uint16_t nauth;     /* Authority PRs         */
    uint16_t nother;    /* Other PRs             */
#if _WIN32
    #pragma warning( push )
    #pragma warning(disable : 4200) 
#endif    
    uint8_t  data[0];    /* Data, variable length */
#if _WIN32
    #pragma warning( pop )
#endif
};

struct dns_question {
    uint16_t qtype, qclass;
    std::string name;
};

struct dns_packet {
    std::vector<struct dns_question> questions;
    std::vector<struct dns_record> answers;
    
    // Header should appears on the last member
    // Visual Studio Error : Compiler Error C2229
    // Ref : https://msdn.microsoft.com/en-us/library/0scy7z2d.aspx
    struct header header;
};


const uint8_t* parse_answer(const uint8_t *pkt, int len, const uint8_t *p,
                            unsigned count, std::vector<struct dns_record> &r, enum dns_response_type respt);


struct dns_packet parse_udp_packet(const uint8_t *pkt, int len);

unsigned serialize_udp_packet(struct dns_packet *in, uint8_t *out);

int nonblock(int fd);

#endif

