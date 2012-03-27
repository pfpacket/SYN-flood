
#include <iostream>
#include <fstream>
#include <string>
#include <stdexcept>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/format.hpp>
#include "raw_tcp.hpp"
#include "tcp_header.hpp"

// Return resolved string of IP address by using template parameter, protocol
template< typename protocol = boost::asio::ip::tcp >
std::string hostname_resolver(const char* hostname, std::string hint = "")
{
    boost::asio::io_service io_service;
    typename protocol::resolver resolver(io_service);
    typename protocol::resolver::query squery(hostname, hint.c_str());
    typename protocol::resolver::iterator it = resolver.resolve(squery);
    return it->endpoint().address().to_string();
}

bool running = true;

void sighandler(const boost::system::error_code &error, int signo, bool &flag) {
    if( error )
        return;
    std::cout << " [*] Stop working" << std::endl;
    flag = false;
}

int main(int argc, char **argv)
{
    int i = 1;
    try {
        std::cout << "TCP SYN sender" << std::endl;
        if( argc < 5 )
            throw std::string("Arguments are too few");

        std::cout << "TCP packet with SYN flag: " << argv[1] << " -> " << argv[2] << ':' << argv[3] << " times=" << argv[4] << std::endl;
        // Resolve hostname by using boost::asio::ip::raw_tcp
        std::string result = hostname_resolver<boost::asio::ip::raw_tcp>(argv[2]);
        std::cout << "hostname: " << argv[2] << "=" << result << std::endl;
        
        // Make endpoint of boost::asio::ip::ether
        boost::asio::io_service io_service;
        boost::asio::ip::raw_tcp::socket socket(io_service, boost::asio::ip::raw_tcp::v4());
        boost::asio::ip::raw_tcp::resolver resolver(io_service);
        boost::asio::ip::raw_tcp::resolver::query query(boost::asio::ip::raw_tcp::v4(), argv[2], "");
        boost::asio::ip::raw_tcp::endpoint destination = *resolver.resolve(query);

        // Create syn packets and send them to the target
        boost::asio::streambuf request_buffer;
        std::ostream os(&request_buffer);
        tcp_header syn_packet(argv[1], result);
        syn_packet.source(34393);
        syn_packet.dest(atoi(argv[3]));
        syn_packet.doff(20/4);
        syn_packet.syn(true);
        syn_packet.seq(0x81b4b626);
        syn_packet.window(32792);
        os << syn_packet;
        int num = atoi(argv[4]);
        for( ; running && i <= num; ++i ) {
            socket.send_to(request_buffer.data(), destination);
            // "\033[2K" - Escape Sequence to move the cursor to the begin of line
            std::cout << "\033[100D" << "[*] Sent TCP(SYN) packet to " << result << " seq=" << i << std::flush;
            io_service.run();
        }
    } catch( std::exception &e ) {
        std::cerr << std::endl << " [-] Exception: " << e.what() << std::endl;
    } catch( std::string &e ) {
        std::cerr << " [-] Exception: " << e << std::endl;
        std::cout << "Usage: " << argv[0] << " SRC_IP DEST_IP PORT NUM" << std::endl;
    }
    std::cout << "[*] Total: " << i-1 << " packets sent" << std::endl;
    return 0;
}
