
#include <algorithm>
#include <netinet/in.h>
#include <string.h>

#include "tadns_common.h"

unsigned fetch(const uint8_t *pkt, const uint8_t *s, int pktsiz, char *dst, int dstlen) {
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

const uint8_t* parse_answer(const uint8_t *pkt, int len, const uint8_t *p, unsigned count,
                            std::vector<struct dns_record> &r, enum dns_response_type respt) {

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
        rec.rtype = (enum dns_record_type)type,
        rec.ttl = ttl;
        rec.name = std::string(name);
        rec.resptype = respt;

        std::transform(rec.name.begin(), rec.name.end(), rec.name.begin(), ::tolower);

        if (type == DNS_MX_RECORD ||
            type == DNS_NS_RECORD ||
            type == DNS_CNAME_RECORD) {

            const uint8_t *poff = type == DNS_MX_RECORD ? &p[2] : p;

            fetch(pkt, poff, len, name, sizeof(name) - 1);
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

// Returns a parsed packet
struct dns_packet parse_udp_packet(const uint8_t *pkt, int len) {
    const uint8_t *e = pkt + len;
    struct header *h = (struct header*)pkt;

    struct dns_packet ret;
    ret.header.tid      = ntohs(h->tid);
    ret.header.flags    = ntohs(h->flags);
    ret.header.nqueries = ntohs(h->nqueries);
    ret.header.nanswers = ntohs(h->nanswers);
    ret.header.nauth    = ntohs(h->nauth);
    ret.header.nother   = ntohs(h->nother);

    const uint8_t *p = &h->data[0];

    for (unsigned i = 0; i < ret.header.nqueries; i++) {
        char name[1025];
        p += fetch(pkt, p, len, name, sizeof(name) - 1);

        if (p + 4 >= e) return ret;

        // Skip to answer section
        p += 4;

        struct dns_question q;
        q.qtype  = ((uint16_t*)p)[0];
        q.qclass = ((uint16_t*)p)[1];
        q.name = std::string(name);

        ret.questions.push_back(q);
    }

    p = parse_answer(pkt, len, p, ret.header.nanswers, ret.answers, RESPONSE_ANSWER);
    p = parse_answer(pkt, len, p, ret.header.nauth,    ret.answers, RESPONSE_AUTHORITATIVE);
    p = parse_answer(pkt, len, p, ret.header.nother,   ret.answers, RESPONSE_ADDITIONAL);

    return ret;
}

unsigned serializeName(std::string dom, uint8_t *out) {
    uint8_t * oout = out;
    unsigned off = 0;
    while (off < dom.size()) {
        auto s = dom.find('.', off);
        unsigned l = (s != std::string::npos) ? s - off : dom.size() - off;
        unsigned a = (s != std::string::npos) ? l + 1 : l;

        *out++ = l;
        memcpy(out, &dom[off], l);
        out += l;
        off += a;
    }
    *out++ = 0;

    return out - oout;  
}

unsigned serialize_answer(const struct dns_record *rec, uint8_t *out) {
    uint8_t * oout = out;

    bool namec = (rec->rtype == DNS_MX_RECORD || 
                  rec->rtype == DNS_NS_RECORD ||
                  rec->rtype == DNS_CNAME_RECORD);

    // Getting the size is a bit convoluted depending on type and the domain itself
    unsigned dlen = namec ? (rec->addr.size() ? rec->addr.size() + 2 : 1) : rec->addr.size();

    // Name goes first
    out += serializeName(rec->name, out);

    ((uint16_t*)out)[0] = htons(rec->rtype);
    ((uint16_t*)out)[1] = htons(0x0001);  // Assuming Internet yo!
    ((uint32_t*)out)[1] = htonl(rec->ttl);
    ((uint16_t*)out)[4] = htons(dlen);
    out += 10;

    if (namec) {
        out += serializeName(rec->addr, out);
    } else {
        memcpy(out, rec->addr.data(), rec->addr.size());
        out += rec->addr.size();
    }

    return out - oout;
}


unsigned serialize_udp_packet(struct dns_packet *in, uint8_t *out) {
    uint8_t *oout = out;
    const uint8_t *e = out + DNS_PACKET_LEN;
    struct header *h = (struct header*)out;

    h->tid      = htons(in->header.tid);
    h->flags    = htons(in->header.flags);
    h->nqueries = htons(in->header.nqueries);
    h->nanswers = htons(in->header.nanswers);
    h->nauth    = htons(in->header.nauth);
    h->nother   = htons(in->header.nother);

    out = &h->data[0];

    for (const auto &q: in->questions) {
        unsigned s = serializeName(q.name, out);
        out += s;

        if (out + 4 >= e) return 0;

        ((uint16_t*)out)[0] = htons(q.qtype);
        ((uint16_t*)out)[1] = htons(q.qclass);
        out += 4;
    }

    for (unsigned i = 0; i < RESPONSE_LAST; i++) {
        for (const auto &r: in->answers) {
            if (r.resptype == i) {
                out += serialize_answer(&r, out);
            }
        }
    }

    return out - oout;
}



