#include <cstring>
#include <string>
#include <iostream>

#if 0
#include <boost/asio.hpp>
#else
#include "asio/asio.hpp"
#endif

using namespace std;
using namespace boost;

char addr_str[32] = "8.8.8.8";

int main(int argc, char * argv[]) {
	if(argc > 1) {
		strncpy(addr_str, argv[1], sizeof(addr_str)-1);
	}		
  asio::ip::address_v4 ipa = asio::ip::address_v4::from_string(addr_str);    
  asio::ip::tcp::endpoint ep;
  ep.address(ipa);

  asio::io_service io_service;
  asio::ip::tcp::resolver resolver(io_service);
  asio::ip::tcp::resolver::iterator destination = resolver.resolve(ep);

	for(auto it = resolver.resolve(ep); it != decltype(it){}; ++it) {
	  cout << it->host_name() << endl;
	}

  return 0;
}
