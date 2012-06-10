#ifndef TCP_HEADER_HPP
#define TCP_HEADER_HPP 1

//
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |          Source Port          |       Destination Port        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                        Sequence Number                        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Acknowledgment Number                      |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |  Data |           |U|A|P|R|S|F|                               |
//  | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
//  |       |           |G|K|H|T|N|N|                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |           Checksum            |         Urgent Pointer        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                    Options                    |    Padding    |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                             data                              |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//           TCP Header Format From the Figure 3 of RFC 793
//

#include <string>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <cstdint>
#include <netdb.h>
#include <netinet/tcp.h>
// For struct tcphdr
/*
   struct tcphdr {
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
    u_int16_t res1:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
  };
*/
#include "protocol_header.hpp"

class tcp_header : public protocol_header {
public:
 
    enum { DEFAULT_WINVAL = 4096 };
    typedef struct tcphdr header_type;

    tcp_header() : rep_{0} {}
    explicit tcp_header(const header_type &tcph) : rep_(tcph) {}
    ~tcp_header() {}

    unsigned char source() const { return ntohs(rep_.source); }
    unsigned char dest() const { return ntohs(rep_.dest); }
    unsigned int seq() const { return ntohl(rep_.seq); }
    unsigned int ack_seq() const { return ntohl(rep_.ack_seq); }
    unsigned short res1() const { return rep_.res1; }
    unsigned short doff() const { return rep_.doff; }
    unsigned short fin() const { return rep_.fin; }
    unsigned short syn() const { return rep_.syn; }
    unsigned short rst() const { return rep_.rst; }
    unsigned short psh() const { return rep_.psh; }
    unsigned short ack() const { return rep_.ack; }
    unsigned short urg() const { return rep_.urg; }
    unsigned short res2() const { return rep_.res2; }
    unsigned short window() const { return ntohs(rep_.window); }
    unsigned short check() const { return ntohs(rep_.check); }
    unsigned short urg_ptr() const { return ntohs(rep_.urg_ptr); }

    void source(unsigned short source) { rep_.source = htons(source); }
    void dest(unsigned short dest) { rep_.dest = htons(dest); }
    void seq(unsigned int seq) { rep_.seq = htonl(seq); }
    void ack_seq(unsigned int ack_seq) { rep_.ack_seq = htonl(ack_seq); }
    void res1(unsigned short res1) { rep_.res1 = res1; }
    void doff(unsigned short doff) { rep_.doff = doff; }
    void fin(bool fin) { rep_.fin = (fin) ? 1 : 0; }
    void syn(bool syn) { rep_.syn = (syn) ? 1 : 0; }
    void rst(bool rst) { rep_.rst = (rst) ? 1 : 0; }
    void psh(bool psh) { rep_.psh = (psh) ? 1 : 0; }
    void ack(bool ack) { rep_.ack = (ack) ? 1 : 0; }
    void urg(unsigned short urg) { rep_.urg = urg; }
    void res2(unsigned short res2) { rep_.res2 = res2; }
    void window(unsigned short window) { rep_.window = htons(window); }
    void check(unsigned short check) { rep_.check = htons(check); }
    void urg_ptr(unsigned short urg_ptr) { rep_.urg_ptr = htons(urg_ptr); }

    int length() const { return sizeof(rep_); }
    char* get_header() { return reinterpret_cast<char*>(&rep_); }
    const struct tcphdr& get() const { return rep_; }

    void compute_checksum(uint32_t srcaddr, uint32_t destaddr) {
        check(0);
        tcp_checksum tc = {{0}, {0}};
        tc.pseudo.ip_src   = htonl(srcaddr);
        tc.pseudo.ip_dst   = htonl(destaddr);
        tc.pseudo.zero     = 0;
        tc.pseudo.protocol = IPPROTO_TCP;
        tc.pseudo.length   = htons(sizeof(tcphdr));
        tc.tcphdr = rep_;
        rep_.check = ((checksum(reinterpret_cast<unsigned short*>(&tc), sizeof(struct tcp_checksum))));
    }

    void compute_checksum(const std::string &srcaddr, const std::string &destaddr) {
        compute_checksum(
                boost::asio::ip::address_v4::from_string(srcaddr).to_ulong(), 
                boost::asio::ip::address_v4::from_string(destaddr).to_ulong()
                );
    }

private:

    //
    //  +--------+--------+--------+--------+
    //  |           Source Address          |
    //  +--------+--------+--------+--------+
    //  |         Destination Address       |
    //  +--------+--------+--------+--------+
    //  |  zero  |  PTCL  |    TCP Length   |
    //  +--------+--------+--------+--------+
    //
    //       TCP PSEUDO HEADER FROM RFC 793
    //
    struct tcph_pseudo {    // TCP pseudo header for header checksum
            uint32_t ip_src;    // Source IP address
            uint32_t ip_dst;    // Destination IP address
            uint8_t zero;      // Always 0
            uint8_t  protocol;  // IPPROTO_TCP
            uint16_t length;    // tcp header length + payload length (Not contained pseudo header)
    };

    struct tcp_checksum {
            struct tcph_pseudo pseudo;
            header_type tcphdr;
    };
    
    header_type rep_;
};

#endif  // TCP_HEADER_HPP
