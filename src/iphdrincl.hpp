//
// ip_hdrincl.hpp
// Enable IP_HDRINCL of raw socket
// This is available only for basic_raw_socket
//
#ifndef BOOST_ASIO_IP_HDRINCL_SOCKOPT
#define BOOST_ASIO_IP_HDRINCL_SOCKOPT

#include <netinet/in.h>
#include <sys/socket.h>

namespace boost {
namespace asio {
namespace ip {
    
// This meets SettableSocketOption requirement
// See the documents of Boost.Asio for more information
class ip_hdrincl {
public:
    ip_hdrincl() : one(1) {}
    ~ip_hdrincl() {}

    template<typename Protocol>
    int level(Protocol p) const { return SOL_IP; }

    template<typename Protocol>
    int name(Protocol p)  const { return IP_HDRINCL; }

    template<typename Protocol>
    const void *data(Protocol p) const { return reinterpret_cast<const void*>(&one); }

    template<typename Protocol>
    int size(Protocol p) const { return sizeof(one); }
private:
    int one;
};

} // namespace ip
} // namespace asio
} // namespace boost

#endif // BOOST_ASIO_IP_HDRINCL_SOCKOPT

