
#include <iostream>
#include <string>
#include <stdexcept>
#include <cmath>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/format.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include "raw_tcp.hpp"
#include "ip_header.hpp" 
#include "tcp_header.hpp"
#include "iphdrincl.hpp"

template<typename protocol = boost::asio::ip::tcp>
std::string hostname_resolver(const char* hostname, std::string hint = "")
{
    boost::asio::io_service io_service;
    typename protocol::resolver resolver(io_service);
    typename protocol::resolver::query squery(hostname, hint.c_str());
    typename protocol::resolver::iterator it = resolver.resolve(squery);
    return it->endpoint().address().to_string();
}

void set_syn_packet(std::ostream &os, std::string dest, std::string dport)
{    
    ip_header iphdr;
    iphdr.version(4);
    iphdr.ihl(iphdr.length() / ip_header::IP_LENGTH_UNIT);
    iphdr.tos(0x10);
    iphdr.ttl(ip_header::IP_DEFAULT_TTL);
    iphdr.frag_off(IP_DF);
    iphdr.protocol(IPPROTO_TCP);
    iphdr.saddr(rand());
    iphdr.daddr(iphdr.address_to_binary(dest));

    tcp_header tcp_syn_header(iphdr.address_to_string(iphdr.saddr()), dest);
    tcp_syn_header.source(rand());
    tcp_syn_header.dest(std::atoi(dport.c_str()));
    tcp_syn_header.doff(20/4);
    tcp_syn_header.syn(true);
    tcp_syn_header.seq(0x81b4b626);
    tcp_syn_header.window(32792);
     
    iphdr.tot_len(iphdr.length() + tcp_syn_header.length());
    iphdr.check();
    os << iphdr << tcp_syn_header; 
}
 
int main(int argc, char **argv)
{
    int i = 1;
    try {
        std::srand(std::time(NULL));
        std::cout << "TCP SYN sender" << std::endl;
        if( argc < 4 )
            throw std::string("Arguments are too few");
        std::cout << "TCP packet with SYN flag: " << " -> " << argv[1] << ':' << argv[2] << " times=" << argv[3] << std::endl;
        std::string result = hostname_resolver<boost::asio::ip::raw_tcp>(argv[1]);
        std::cout << "hostname: " << argv[1] << "=" << result << std::endl;
        
        boost::asio::io_service io_service;
        boost::asio::ip::raw_tcp::socket socket(io_service, boost::asio::ip::raw_tcp::v4());
        boost::system::error_code ec;
        boost::asio::ip::ip_hdrincl iphdrincl;
        socket.set_option(iphdrincl, ec);
        boost::asio::ip::raw_tcp::resolver resolver(io_service);
        boost::asio::ip::raw_tcp::resolver::query query(boost::asio::ip::raw_tcp::v4(), argv[1], "");
        boost::asio::ip::raw_tcp::endpoint destination = *resolver.resolve(query);

        boost::asio::streambuf request_buffer;
        std::ostream os(&request_buffer);
        int num = std::atoi(argv[3]);
        for( ; i <= num; ++i ) {
            set_syn_packet(os, result, argv[2]);
            socket.send_to(request_buffer.data(), destination);
            std::cout << "\033[100D" << "[*] Sent TCP(SYN) packet to " << result << " seq=" << i << std::flush;
            request_buffer.consume(request_buffer.size());
//            io_service.run();
//            io_service.reset();
        }
    } catch( std::exception &e ) {
        std::cerr << std::endl << "[-] Exception: " << e.what() << std::endl;
    } catch( std::string &e ) {
        std::cerr << "[-] Exception: " << e << std::endl;
        std::cout << "Usage: " << argv[0] << " DEST_IP PORT NUM" << std::endl;
    }
    std::cout << "[*] Total: " << i-1 << " packets sent" << std::endl;
    return 0;
}

