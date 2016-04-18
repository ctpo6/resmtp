#ifndef _SMTP_CLIENT_H_
#define _SMTP_CLIENT_H_

#include <functional>
#include <memory>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/noncopyable.hpp>

#include "net/dns_resolver.hpp"

#include "check.h"
#include "envelope.h"
#include "log.h"
#include "options.h"
#include "smtp_backend_manager.h"


using std::string;
using std::vector;


class smtp_client :
	public std::enable_shared_from_this<smtp_client>,
	private boost::noncopyable
{
public:

	smtp_client(boost::asio::io_service &io_service,
							smtp_backend_manager &bm);

	typedef std::function<void () > complete_cb_t;

#if 0
	void start(const check_data_t &_data,
						 complete_cb_t complete,
						 envelope_ptr _envelope,
						 const server_parameters::remote_point &_remote,
						 const char *_proto_name,
						 const std::vector<std::string> &dns_servers);
#endif

	// start SMTP session; execute commands until DATA
	void start_smtp_session(const check_data_t &_data,
    const vector<boost::asio::ip::address_v4> &dns_servers,
    envelope &e,
    complete_cb_t complete_cb);
	
	// continue session started with start_smtp_session()
	void continue_smtp_session(envelope &e, 
    complete_cb_t complete_cb);

	void stop();


	const check_data_t & get_check_data() const { return m_data;	}

protected:

	enum class proto_state_t {
		start = 0,
		resolved,
		connected,
		after_hello,
		after_xclient,
		after_hello_xclient,
		after_mail,
		after_rcpt,
		after_data,
		after_dot,
		after_quit,
		error
	};
	// !!! update this function together with enum
	static const char * get_proto_state_name(proto_state_t st);

	smtp_backend_manager &backend_mgr;

	boost::asio::ip::tcp::socket m_socket;
	boost::asio::io_service::strand strand_;

	// used to resolve backend server
	y::net::dns::resolver m_resolver;

	boost::asio::deadline_timer m_timer;

#ifdef RESMTP_LMTP_SUPPORT
	bool m_lmtp;
#endif  

	bool m_use_xclient;
	bool m_use_pipelining;

	string m_read_buffer;

	complete_cb_t cb_complete;

	envelope *m_envelope = nullptr;

	proto_state_t m_proto_state;

	check_data_t m_data;

	smtp_backend_manager::backend_host backend_host;
	string backend_host_ip;

	string m_line_buffer;

	// our request to backend
	boost::asio::streambuf client_request;

	boost::asio::streambuf backend_response;

	envelope::rcpt_list_t::iterator m_current_rcpt;

	uint32_t m_timer_value;

  
	void start_with_next_backend();

	void do_stop();

	void start_read_line();

	void handle_read_smtp_line(const boost::system::error_code &ec);

	bool process_answer(std::istream &_stream);

  // handles connect to the server specified with IP address
	void handle_simple_connect(const boost::system::error_code &ec);
  
  // handles connect to the server specified with symbolic name
	void handle_connect(const boost::system::error_code &ec,
											y::net::dns::resolver::iterator);
  
	void handle_resolve(const boost::system::error_code &ec,
											y::net::dns::resolver::iterator);

	void handle_write_request(const boost::system::error_code &ec, size_t sz, const std::string& s);
	void handle_write_data_request(const boost::system::error_code &ec, size_t sz);

	void handle_timer(const boost::system::error_code &ec);
	void restart_timeout();

	// log delivery status for each recipient
	check::chk_status report_rcpt(bool success,
																string log_msg,
																string remote_answer);


	// called on error (protocol, network, etc.) after connection with backend was established
	void fault(string log_msg,
						 string remote_answer);
	// called on backend host resolve or connection error
	void fault_backend();
	// called when all backends are currently unavailable
	void fault_all_backends();

  // called if SMTP session started with smtp_session_start() has executed
  // successfully all commands until DATA
  void session_start_success();
  
  // called if SMTP session continued with smtp_session_continue() has executed
  // successfully until it's quit
	void session_success();

	void on_backend_ip_address();
	void on_backend_conn();

	void log(resmtp::log prio, const string &msg) noexcept;
};

typedef std::shared_ptr<smtp_client> smtp_client_ptr;

#endif // _SMTP_CLIENT_H_
