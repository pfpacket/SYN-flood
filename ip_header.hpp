#ifndef IP_HEADER_HPP
#define IP_HEADER_HPP

#include <iostream>
#include <string>
#include <netdb.h>
#include <netinet/ip.h>
#include <boost/asio.hpp>

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

class ip_header {
public:
    ip_header() : rep_{0} {}
    ~ip_header() {}
    
    unsigned int version() const { return rep_.version; }
    unsigned int ihl() const { return rep_.ihl; }
    u_int8_t tos() const { return rep_.tos; }
    u_int8_t tot_len() const { return rep_.tot_len; }
    u_int8_t id() const { return rep_.id; }
    u_int8_t frag_off() const { return rep_.frag_off; }
    u_int8_t ttl() const { return rep_.ttl; }
    u_int8_t protocol() const { return rep_.protocol; }
    u_int16_t check() const { return htons(rep_.check); }
    u_int32_t saddr() const { return htonl(rep_.saddr); }
    u_int32_t daddr() const { return htonl(rep_.daddr); }
    
    void version(unsigned int version) { rep_.version = version; }
    void ihl(unsigned int ihl) { rep_.ihl = ihl; }
    void tos(u_int8_t tos) { rep_.tos = tos; }
    void tot_len(u_int8_t tot_len) { rep_.tot_len = tot_len; }
    void id(u_int8_t id) { rep_.id = id; }
    void frag_off(u_int8_t frag_off) { rep_.frag_off = frag_off; }
    void ttl(u_int8_t ttl) { rep_.ttl = ttl; }
    void protocol(u_int8_t protocol) { rep_.protocol = protocol; }
    void check(u_int16_t check) { rep_.check = htons(check); }
    void check() { check(0); check( checksum(reinterpret_cast<unsigned short*>(&rep_), length()) ); }
    void saddr(u_int32_t saddr) { rep_.saddr = htonl(saddr); }
    void daddr(u_int32_t daddr) { rep_.daddr = htonl(daddr); }

    static int length() { return sizeof(struct iphdr); }

    friend std::istream& operator>>(std::istream& is, ip_header& header) {
        return is.read(reinterpret_cast<char*>(&(header.rep_)), header.length());
    }

    friend std::ostream& operator<<(std::ostream& os, ip_header& header) {
        return os.write(reinterpret_cast<char*>(&(header.rep_)), header.length());
    }
   
    u_int32_t address_to_binary(std::string &straddr) {
        return boost::asio::ip::address_v4::from_string(straddr).to_ulong();
    } 
     
    std::string address_to_string(u_int32_t binaddr) {
        return boost::asio::ip::address_v4(binaddr).to_string();
    } 

private:
    static unsigned short checksum(unsigned short *buf, int bufsz) {
      unsigned long sum = 0;
        while( bufsz > 1 ) {
            sum += *buf++;
            bufsz -= 2;
        }
        if( bufsz == 1 )
            sum += *(unsigned char *)buf;
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        return ~sum;
    }
    struct iphdr rep_;
}; 
 
#endif // IP_HEADER_HPP
