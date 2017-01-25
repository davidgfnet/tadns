
#ifndef TADNS_COMMON____H_
#define TADNS_COMMON____H_

#define DNS_PACKET_LEN      2048    /* Buffer size for DNS packet */

#include "tadns.h"

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

struct dns_question {
	uint16_t qtype, qclass;
	std::string name;
};

struct dns_packet {
	struct header header;
	std::vector<struct dns_question> questions;
	std::vector<struct dns_record> answers;
};


const uint8_t* parse_answer(const uint8_t *pkt, int len, const uint8_t *p,
                            unsigned count, std::vector<struct dns_record> &r, enum dns_response_type respt);


struct dns_packet parse_udp_packet(const uint8_t *pkt, int len);

unsigned serialize_udp_packet(struct dns_packet *in, uint8_t *out);

#endif

