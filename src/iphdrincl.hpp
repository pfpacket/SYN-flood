//
// ip_hdrincl.hpp
// IP_HDRINCL of raw socket
// This is available only for basic_raw_socket
//
#ifndef BOOST_ASIO_IP_HDRINCL_SOCKOPT
#define BOOST_ASIO_IP_HDRINCL_SOCKOPT

#include <netinet/in.h>
#include <sys/socket.h>

namespace boost {
namespace asio {
namespace ip {
    
// This meets SettableSocketOption requirements
// See the documents of Boost.Asio for more information
class ip_hdrincl {
public:
    ip_hdrincl() : optval(1) {}
    ip_hdrincl(bool ov) : optval(ov ? 1 : 0) {}
    ~ip_hdrincl() {}

    template<typename Protocol>
    int level(const Protocol &p) const { return SOL_IP; }

    template<typename Protocol>
    int name(const Protocol &p)  const { return IP_HDRINCL; }

    template<typename Protocol>
    const void *data(const Protocol &p) const { return reinterpret_cast<const void*>(&optval); }

    template<typename Protocol>
    int size(const Protocol &p) const { return sizeof(optval); }
     
private:
    int optval;
};

} // namespace ip
} // namespace asio
} // namespace boost

#endif // BOOST_ASIO_IP_HDRINCL_SOCKOPT

