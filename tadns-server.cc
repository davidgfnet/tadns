/*
 * Copyright (c) 2017 David Guillen Fandos <david@davidgf.net>
 *
 * Released to the Public domain
 *
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <string>
#include <limits>
#include <utility>
#include <arpa/inet.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/poll.h>

#include "tadns.h"
#include "tadns_common.h"

struct dns_response {
    struct dns_packet pkt;

    // src address
    struct sockaddr_storage addrstorage;
    socklen_t addrlen;
};

int listenfd;

void resolved_cb(struct dns_cb_data *cbdata) {
    // Return whatever we found
    struct dns_response *dresp = (struct dns_response*)cbdata->context;

    unsigned numans = 0;
    for (const auto &e: cbdata->replies)
        if (e.resptype == RESPONSE_ANSWER)
            numans++;

    switch (cbdata->error) {
    case DNS_OK:
        dresp->pkt.answers = cbdata->replies;
        dresp->pkt.header.flags = 0x8180;
        dresp->pkt.header.nanswers = numans;
        break;
    case DNS_DOES_NOT_EXIST:
        dresp->pkt.header.flags = 0x8180;
        break;
    case DNS_TIMEOUT:
    case DNS_ERROR:
        dresp->pkt.header.flags = 0x8182;
        break;
    };

    // Blocking send, automatic rate limiting?
    uint8_t tmp[2048];
    unsigned towrite = serialize_udp_packet(&dresp->pkt, tmp);
    sendto(listenfd, tmp, towrite, 0, (struct sockaddr*)&dresp->addrstorage, dresp->addrlen);

    delete dresp;
}

int main(int argc, char *argv[]) {
    const char *prog = argv[0];

    int port = 53;

    //if (argc == 1)
    //    usage(prog);

    DNSResolverIface *dns;
    if ((dns = createResolver(NULL, 10)) == NULL) {
        (void) fprintf(stderr, "failed to init resolver\n");
        exit(EXIT_FAILURE);
    }

    // Bind port!
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);

    listenfd = socket(AF_INET, SOCK_DGRAM, 0);
    int yes = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    if (bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        printf("Error %u binding the port.\n", errno); perror("bind");
        exit(EXIT_FAILURE);
    }

    int epollfd = epoll_create(1);
    auto dnsfds = dns->getFds();

    struct epoll_event ev;
    ev.events = POLLIN;
    ev.data.ptr = NULL;

    epoll_ctl(epollfd, EPOLL_CTL_ADD, dnsfds.first,  &ev);
    epoll_ctl(epollfd, EPOLL_CTL_ADD, dnsfds.second, &ev);
    epoll_ctl(epollfd, EPOLL_CTL_ADD, listenfd,      &ev);

    while (1) {
        // Wait for stuff to happen
        struct epoll_event t;
        epoll_wait(epollfd, &t, 1, 1000);
        
        // Receive packets!
        uint8_t inbuff[2048];
        struct sockaddr_storage addrstorage;
        socklen_t addrlen = sizeof(addrstorage);
        int received = recvfrom(listenfd, inbuff, sizeof(inbuff), MSG_DONTWAIT, (sockaddr*)&addrstorage, &addrlen);

        if (received > 0) {
            struct dns_packet pkt = parse_udp_packet(inbuff, received);

            // Just look at the first question for now
            if (pkt.questions.size() == 1 && pkt.questions[0].qclass == 1) {
                // Create response
                struct dns_response *dresp = new struct dns_response;

                dresp->pkt.header.tid = pkt.header.tid;
                dresp->pkt.header.nqueries = 1;
                dresp->pkt.header.nanswers = 0;
                dresp->pkt.header.nauth = 0;
                dresp->pkt.header.nother = 0;

                memcpy(&dresp->addrstorage, &addrstorage, addrlen);
                dresp->addrlen = addrlen;

                dresp->pkt.questions.push_back(pkt.questions[0]);

                dns->resolve(dresp, pkt.questions[0].name, (enum dns_record_type)pkt.questions[0].qtype, resolved_cb);
            }
        }

        // Process requests!
        dns->poll();
    }

    delete dns;

    return (EXIT_SUCCESS);
}


