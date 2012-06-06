#ifndef IP_HEADER_HPP
#define IP_HEADER_HPP

#include <iostream>
#include <string>
#include <netdb.h>
#include <netinet/ip.h>
#include <boost/asio/ip/address.hpp>
#include "protocol_header.hpp"

//
// Define a ip header class
//

/*
struct iphdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error	"Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    // The options start here.
  };
*/

class ip_header : public protocol_header {
public:
    enum { IP_LENGTH_UNIT = 4, IP_DEFAULT_TTL = IPDEFTTL }; 
    typedef struct iphdr header_type;

    ip_header() : rep_{0} {}
    ~ip_header() {}
    
    unsigned int version() const { return rep_.version; }
    unsigned int ihl() const { return rep_.ihl; }
    u_int8_t tos() const { return rep_.tos; }
    u_int16_t tot_len() const { return ntohs(rep_.tot_len); }
    u_int16_t id() const { return ntohs(rep_.id); }
    u_int16_t frag_off() const { return ntohs(rep_.frag_off); }
    u_int8_t ttl() const { return rep_.ttl; }
    u_int8_t protocol() const { return rep_.protocol; }
    u_int16_t check() const { return ntohs(rep_.check); }
    u_int32_t saddr() const { return ntohl(rep_.saddr); }
    u_int32_t daddr() const { return ntohl(rep_.daddr); }
    
    void version(unsigned int version) { rep_.version = version; }
    void ihl(unsigned int ihl) { rep_.ihl = ihl; }
    void tos(u_int8_t tos) { rep_.tos = tos; }
    void tot_len(u_int16_t tot_len) { rep_.tot_len = htons(tot_len); }
    void id(u_int16_t id) { rep_.id = htons(id); }
    void frag_off(u_int16_t frag_off) { rep_.frag_off = htons(frag_off); }
    void ttl(u_int8_t ttl) { rep_.ttl = ttl; }
    void protocol(u_int8_t protocol) { rep_.protocol = protocol; }
    void check(u_int16_t check) { rep_.check = htons(check); }
    void check() { check(0); check( checksum(reinterpret_cast<unsigned short*>(&rep_), length()) ); }
    void saddr(u_int32_t saddr) { rep_.saddr = htonl(saddr); }
    void daddr(u_int32_t daddr) { rep_.daddr = htonl(daddr); }

    int length() const { return sizeof(rep_); }
    char *get_header() { return reinterpret_cast<char*>(&rep_); }
     
private:
   struct iphdr rep_;
}; 
 
#endif // IP_HEADER_HPP
