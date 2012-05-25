#ifndef PROTOCOL_HEADER_HPP
#define PROTOCOL_HEADER_HPP

#include <iostream>
#include <boost/asio/ip/address.hpp>
 
//
// class protocol_header
// An abstrace base class of each protocol headers
//
class protocol_header {
public:
    protocol_header() {}
    virtual ~protocol_header() {}
    
    virtual int length() const = 0;
    virtual char *get_header() = 0;
    
    static u_int32_t address_to_binary(std::string &&straddr) {
        return boost::asio::ip::address_v4::from_string(straddr).to_ulong();
    } 
     
    static std::string address_to_string(u_int32_t binaddr) {
        return boost::asio::ip::address_v4(binaddr).to_string();
    } 
     
    friend std::istream& operator>>(std::istream& is, protocol_header& header);
    friend std::ostream& operator<<(std::ostream& os, protocol_header& header);

protected:    
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
     
    virtual void prepare_to_read(std::istream&) = 0;
    virtual void prepare_to_write(std::ostream&) = 0;
};

inline std::istream& operator>>(std::istream& is, protocol_header& header) {
    header.prepare_to_read(is);
    return is.read(header.get_header(), header.length());
}

inline std::ostream& operator<<(std::ostream& os, protocol_header& header) {
    header.prepare_to_write(os);
    return os.write(header.get_header(), header.length());
}

#endif // PROTOCOL_HEADER_HPP

