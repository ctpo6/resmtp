// simple.cpp : Simple console based application to query some DNS servers
//
#include <boost/net/resolve.hpp>
#include <iostream>

using namespace std;
using namespace boost;
using namespace boost::net;

void show_message(dns::message & dns_message);

void request( dns::message & dns_message ) {
  boost::asio::io_service ioservice;
  dns::resolve resolver;

  ip::address rambler_dns_1( ip::address::from_string("81.19.70.16") );
  ip::address rambler_dns_2( ip::address::from_string("81.19.94.163") );
  resolver.addServer( rambler_dns_1 );
  resolver.addServer( rambler_dns_2 );

  // Resolve the message and show the results
  show_message( resolver.query(dns_message) );
}

void test_bl() {
	cout << "#################### TEST BL ##################\n";
	cout << "BAD pbl.spamhaus.org ----------------------------\n";
	dns::message test_rbl_bad_a1("67.44.160.1.pbl.spamhaus.org", dns::type_a );
  request( test_rbl_bad_a1 );
	// dns::message test_rbl_bad_txt1("67.44.160.1.pbl.spamhaus.org", dns::type_txt );
  // request( test_rbl_bad_txt1 );
	cout << "BAD pbl.spamhaus.org ----------------------------\n\n\n\n\n";

	cout << "BAD bl.spamcop.net ----------------------------\n";
	dns::message test_rbl_bad_a2("133.100.46.89.bl.spamcop.net", dns::type_a );
  request( test_rbl_bad_a2 );
	// dns::message test_rbl_bad_txt2("133.100.46.89.bl.spamcop.net", dns::type_txt );
  // request( test_rbl_bad_txt2 );
	cout << "BAD bl.spamcop.net ----------------------------\n\n\n\n\n";

	cout << "GOOD bl.spamcop.net ---------------------------------------------\n";
	dns::message test_rbl_good_a1("67.44.160.1.bl.spamcop.net", dns::type_a );
  request( test_rbl_good_a1 );
	// dns::message test_rbl_good_txt1("67.44.160.1.bl.spamcop.net", dns::type_txt );
  // request( test_rbl_good_txt1 );
	cout << "GOOD bl.spamcop.net ---------------------------------------------\n\n\n\n\n";
}


void test_wl() {
	cout << "#################### TEST WL ##################\n";
	cout << "GOOD list.dnswl.org ----------------------------\n";
	dns::message test_wl_good_a1("26.66.19.81.list.dnswl.org", dns::type_a );
  request( test_wl_good_a1 );
	dns::message test_wl_good_txt1("26.66.19.81.list.dnswl.org", dns::type_txt );
  request( test_wl_good_txt1 );
	cout << "GOOD list.dnswl.org ----------------------------\n\n\n\n\n";
	
	cout << "BAD list.dnswl.org ----------------------------\n";
	dns::message test_wl_bad_a1("133.100.46.89.list.dnswl.org", dns::type_a );
  request( test_wl_bad_a1 );
	dns::message test_wl_bad_txt1("133.100.46.89.list.dnswl.org", dns::type_txt );
  request( test_wl_bad_txt1 );
	cout << "BAD list.dnswl.org ----------------------------\n\n\n\n\n";
}

int main(int argc, char* argv[]) {
	// test_bl();
	test_wl();
	
  // dns::message test_a("cnn.com", dns::type_a );
	// dns::message test_a("mail.rambler.ru", dns::type_mx );
  // request( test_a );

	// dns::message test_rbl_a1("1.0.0.127.grey-whitelist.rambler.ru", dns::type_a );
  // request( test_rbl_a1 );

	// dns::message test_rbl_a("214.63.37.122.grey-whitelist.rambler.ru", dns::type_a );
  // request( test_rbl_a );

	// dns::message test_rbl_txt("214.63.37.122.grey-whitelist.rambler.ru", dns::type_txt );
  // request( test_rbl_txt );
	
/*
  dns::message test_rbl_a("214.63.37.122.sbl-xbl.spamhaus.org", dns::type_a );
  request( test_rbl_a );

  dns::message test_rbl_txt("214.63.37.122.sbl-xbl.spamhaus.org", dns::type_txt );
  request( test_rbl_txt );

  dns::message test_ns("cnn.com", dns::type_ns );
  request( test_ns );

  dns::message test_cname("cnn.com", dns::type_cname );
  request( test_cname );

  dns::message test_soa("cnn.com", dns::type_soa );
  request( test_soa );

  dns::message test_ptr("181.132.57.208.in-addr.arpa.", dns::type_ptr );
  request( test_ptr );

  dns::message test_hinfo("cnn.com", dns::type_hinfo );
  request( test_hinfo );

  dns::message test_mx("mpowercom.com", dns::type_mx );
  request( test_mx );

  dns::message test_txt("mpowercom.com", dns::type_txt );
  request( test_txt );

  // Service Records aren't supported, *yet*
  dns::message test_srv("mpowercom.com", dns::type_srv );
  request( test_srv );

  // Won't do anything ...
  dns::message test_axfr("mpowercom.com", dns::type_axfr );
  request( test_axfr );

  // Won't do anything ...
  dns::message test_all("mpowercom.com", dns::type_all );
  request( test_all );

  // this last one will assert
  dns::message test_none("cnn.com", dns::type_none );
  request( test_none );
*/
  return 0;
}
