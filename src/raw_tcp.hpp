#ifndef BOOST_ASIO_IP_RAW_TCP_HPP
#define BOOST_ASIO_IP_RAW_TCP_HPP 1

#include <boost/asio/detail/config.hpp>
#include <boost/asio/detail/socket_types.hpp>
#include <boost/asio/basic_raw_socket.hpp>
#include <boost/asio/ip/basic_endpoint.hpp>
#include <boost/asio/ip/basic_resolver.hpp>
#include <boost/asio/ip/basic_resolver_iterator.hpp>
#include <boost/asio/ip/basic_resolver_query.hpp>
#include <sys/socket.h>
#include <netpacket/packet.h>


#include <boost/asio/detail/push_options.hpp>

namespace boost {
namespace asio {
namespace ip {

class raw_tcp
{
public:
  /// The type of a raw TCP endpoint.
  typedef basic_endpoint<raw_tcp> endpoint;

  /// Construct to represent the  protocol.
  static raw_tcp v4()
  {
    return raw_tcp(IPPROTO_TCP, AF_INET);
  }

  /// Construct to represent the IPv6 TCP protocol.
  static raw_tcp v6()
  {
    return raw_tcp(IPPROTO_TCP, AF_INET);
  }

  /// Obtain an identifier for the type of the protocol.
  int type() const
  {
    return SOCK_RAW;
  }

  /// Obtain an identifier for the protocol.
  int protocol() const
  {
    return protocol_;
  }

  /// Obtain an identifier for the protocol family.
  int family() const
  {
    return family_;
  }

  /// The raw TCP socket type.
  typedef basic_raw_socket<raw_tcp> socket;

  /// The raw TCP resolver type.
  typedef basic_resolver<raw_tcp> resolver;

  /// Compare two protocols for equality.
  friend bool operator==(const raw_tcp& p1, const raw_tcp& p2)
  {
    return p1.protocol_ == p2.protocol_ && p1.family_ == p2.family_;
  }

  /// Compare two protocols for inequality.
  friend bool operator!=(const raw_tcp& p1, const raw_tcp& p2)
  {
    return p1.protocol_ != p2.protocol_ || p1.family_ != p2.family_;
  }

private:
  // Construct with a specific family.
  explicit raw_tcp(int protocol_id, int protocol_family)
    : protocol_(protocol_id),
      family_(protocol_family)
  {
  }

  int protocol_;
  int family_;
};

} // namespace ip
} // namespace asio
} // namespace boost

#include <boost/asio/detail/pop_options.hpp>

#endif // BOOST_ASIO_IP_RAW_TCP_HPP
