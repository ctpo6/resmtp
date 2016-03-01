#include "smtp_connection.h"

#include <algorithm>
#include <cassert>
#include <ctime>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <sstream>
#include <unordered_set>
#include <vector>

#include <boost/bind.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/format.hpp>
#include <boost/type_traits.hpp>

#include "global.h"
#include "header_parser.h"
#include "ip_options.h"
#include "param_parser.h"
#include "rfc_date.h"
#include "rfc822date.h"
#include "smtp_backend_manager.h"
#include "smtp_connection_manager.h"
#include "util.h"


#undef PDBG
#undef PLOG
#ifdef _DEBUG
#define PDBG(fmt, args...) log(r::log::debug, util::strf("%s:%d %s: " fmt, __FILE__, __LINE__, __func__, ##args))
#define PLOG(prio, fmt, args...) log(prio, util::strf("%s:%d %s: " fmt, __FILE__, __LINE__, __func__, ##args))
#else
#define PDBG(fmt, args...)
#define PLOG(prio, fmt, args...)
#endif


using namespace std;
using namespace y::net;
namespace r = resmtp;


const smtp_connection::proto_map_t smtp_connection::smtp_command_handlers {
    {"helo", &smtp_connection::smtp_helo},
    {"ehlo", &smtp_connection::smtp_ehlo},
    {"mail", &smtp_connection::smtp_mail},
    {"rcpt", &smtp_connection::smtp_rcpt},
    {"data", &smtp_connection::smtp_data},
    {"quit", &smtp_connection::smtp_quit},
    {"rset", &smtp_connection::smtp_rset},
    {"noop", &smtp_connection::smtp_noop},
    {"starttls", &smtp_connection::smtp_starttls}
};


smtp_connection::smtp_connection(boost::asio::io_service &_io_service,
                                 smtp_connection_manager &_manager,
                                 smtp_backend_manager &bmgr,
                                 boost::asio::ssl::context& _context)
    : io_service_(_io_service)
    , m_manager(_manager)
    , backend_mgr(bmgr)

    , strand_(_io_service)
    , m_ssl_socket(_io_service, _context)

    , m_resolver(_io_service)

    , m_timer(_io_service)
    , m_tarpit_timer(_io_service)
{
    m_envelope.reset(new envelope(false));
}


boost::asio::ip::tcp::socket& smtp_connection::socket()
{
    return m_ssl_socket.next_layer();
}


void smtp_connection::start(bool force_ssl)
{
    m_force_ssl = force_ssl;

    m_proto_state = STATE_START;
    ssl_state_ = ssl_none;

    m_session_id = envelope::generate_new_id();

    m_connected_ip = socket().remote_endpoint().address();
    log(r::log::debug,
        str(boost::format("**** CONNECT %1%") % m_connected_ip.to_string()));

    m_max_rcpt_count = g::cfg().m_max_rcpt_count;
    // if specified, get the number of recipients for specific IP
    ip_options_config::ip_options_t opt;
    if (g_ip_config.check(m_connected_ip.to_v4(), opt)) {
        m_max_rcpt_count = opt.m_rcpt_count;
    }

    m_timer_value = g::cfg().frontend_cmd_timeout;

    for (const auto &addr: g::cfg().dns_ip) {
        m_resolver.add_nameserver(addr);
    }

    // resolve client IP to host name
    m_remote_host_name.clear();
//    PDBG("call async_resolve() %s", m_connected_ip.to_string().c_str());
    m_resolver.async_resolve(
                util::rev_order_av4_str(m_connected_ip.to_v4(), "in-addr.arpa"),
                dns::type_ptr,
                strand_.wrap(boost::bind(
                                 &smtp_connection::handle_back_resolve,
                                 shared_from_this(), _1, _2)));
}


void smtp_connection::handle_back_resolve(
        const boost::system::error_code& ec,
        dns::resolver::iterator it)
{
    if (!ec) {
        if (auto ptr = boost::dynamic_pointer_cast<dns::ptr_resource>(*it)) {
            m_remote_host_name = util::unfqdn(ptr->pointer());
        }
    } else if (ec == boost::asio::error::operation_aborted) {
        return;
    }

    log(r::log::info,
        str(boost::format("**** CONNECT %1%[%2%]")
            % (m_remote_host_name.empty() ? "[UNAVAILABLE]" : m_remote_host_name.c_str())
            % m_connected_ip.to_string()));

    // DNSBL check is off
    if (g::cfg().dnsbl_hosts.empty()) {
        handle_dnsbl_check();
        return;
    }

    // start DNSBL check
    m_dnsbl_check.reset(new rbl_check(io_service_));
    for (const auto &addr: g::cfg().dns_ip) {
        m_dnsbl_check->add_nameserver(addr);
    }
    for (auto &s: g::cfg().dnsbl_hosts) {
        m_dnsbl_check->add_rbl_source(s);
    }
    m_dnsbl_check->start(m_connected_ip.to_v4(),
                         bind(&smtp_connection::handle_dnsbl_check,
                              shared_from_this()));
}


void smtp_connection::handle_dnsbl_check()
{
    is_blacklisted = m_dnsbl_check->get_status(bl_status_str);
    m_dnsbl_check->stop();
    m_dnsbl_check.reset();

    if (is_blacklisted) {
        g::mon().on_conn_bl();
    }

    if (is_blacklisted || g::cfg().dnswl_host.empty()) {
        // blacklisted connection will be rejected later, after receving 'MAIL FROM:'
        start_proto();
        return;
    }

    // start DNSWL check
    m_dnswl_check.reset(new rbl_check(io_service_));
    for (const auto &addr: g::cfg().dns_ip) {
        m_dnswl_check->add_nameserver(addr);
    }
    m_dnswl_check->add_rbl_source(g::cfg().dnswl_host);
    m_dnswl_check->start(m_connected_ip.to_v4(),
                         bind(&smtp_connection::start_proto,
                              shared_from_this()));
}


void smtp_connection::start_proto()
{
    restart_timeout();

    // get DNSWL check result
    if (m_dnswl_check) {
        string wl_status_str;
        is_whitelisted = m_dnswl_check->get_status(wl_status_str);
        m_dnswl_check->stop();
        m_dnswl_check.reset();
        log(r::log::debug,
            str(boost::format("wl_status_str:%1%") % wl_status_str));
    } else {
        is_whitelisted = false;
    }

    if (is_whitelisted) {
        g::mon().on_conn_wl();
    }

    if (!is_whitelisted && g::cfg().m_tarpit_delay_seconds) {
        on_connection_tarpitted();
    }

    std::ostream response_stream(&m_response);
    string error;
    // returns false on connections number exceeding limits
    if (m_manager.start(shared_from_this(), error)) {
        // send a greeting msg

        response_stream << "220 " << boost::asio::ip::host_name() << " "
                        << (g::cfg().m_smtp_banner.empty() ? "Ok" : g::cfg().m_smtp_banner) << "\r\n";

        if (m_force_ssl) {
            ssl_state_ = ssl_active;
            m_ssl_socket.async_handshake(boost::asio::ssl::stream_base::server,
                strand_.wrap(boost::bind(&smtp_connection::handle_start_hello_write,
                                         shared_from_this(),
                                         boost::asio::placeholders::error,
                                         false)));
        } else {
            send_response(boost::bind(&smtp_connection::handle_write_request,
                                      shared_from_this(),
                                      boost::asio::placeholders::error));
		}
	} else {
		// log bad session for spamhaus
		log_spamhaus(m_connected_ip.to_v4().to_string(),
					 m_helo_host,
					 string());
		log(r::log::notice,
			str(boost::format("%1%[%2%] REJECT: %3%")
				% (m_remote_host_name.empty() ? "[UNAVAILABLE]" : m_remote_host_name.c_str())
				% m_connected_ip.to_v4().to_string()
				% error));
        response_stream << error;

        if (m_force_ssl) {
            ssl_state_ = ssl_active;
    	    m_ssl_socket.async_handshake(boost::asio::ssl::stream_base::server,
            	    strand_.wrap(boost::bind(&smtp_connection::handle_start_hello_write, shared_from_this(),
                                boost::asio::placeholders::error, true)));
        } else {
            send_response(boost::bind(&smtp_connection::handle_last_write_request,
                                      shared_from_this(),
                                      boost::asio::placeholders::error),
                          true);
        }
    }
}


void smtp_connection::on_connection_tarpitted()
{
    tarpit = true;
    g::mon().on_conn_tarpitted();
}


void smtp_connection::on_connection_close()
{
    g::mon().on_conn_closed(close_status, tarpit);
    log(r::log::info,
        str(boost::format("**** DISCONNECT status=%1% tarpit=%2%")
            % resmtp::monitor::get_conn_close_status_name(close_status)
            % tarpit));
}


bool smtp_connection::check_socket_read_buffer_is_empty()
{
    ba::socket_base::bytes_readable command(true);
    socket().io_control(command);
    return command.get() == 0;
}


void smtp_connection::handle_start_hello_write(
        const boost::system::error_code& _error,
        bool _close)
{
    if(_error) {
        return;
    }

	if (_close) {
        send_response(boost::bind(
            &smtp_connection::handle_last_write_request,
            shared_from_this(),
            boost::asio::placeholders::error));
    } else {
        send_response(boost::bind(
            &smtp_connection::handle_write_request,
            shared_from_this(),
            boost::asio::placeholders::error));
    }
}


void smtp_connection::start_read() {
    if (m_proto_state == STATE_CHECK_DATA) {
        m_timer.cancel();               // wait for check to complete
        return;
    }

    restart_timeout();

    size_t unread_size = buffers.size() - m_envelope->orig_message_token_marker_size_;

#if 0
    PDBG("read_pending=%d unread_size=%zu buffers.size()=%zu orig_message_token_marker_size=%zu",
         read_pending,
         unread_size,
         buffers.size(),
         m_envelope->orig_message_token_marker_size_);
#endif

    if (unread_size) {
        handle_read_helper(unread_size);
    }
    else if (!read_pending) {
        if (ssl_state_ == ssl_active) {
            m_ssl_socket.async_read_some(buffers.prepare(512),
                    strand_.wrap(boost::bind(&smtp_connection::handle_read,
                                             shared_from_this(),
                                             boost::asio::placeholders::error,
                                             boost::asio::placeholders::bytes_transferred)));
        }
        else {
            socket().async_read_some(buffers.prepare(512),
                    strand_.wrap(boost::bind(&smtp_connection::handle_read,
                                             shared_from_this(),
                                             boost::asio::placeholders::error,
                                             boost::asio::placeholders::bytes_transferred)));
        }
        read_pending = true;
    }
}

// Parses text as part of the message data from [b, e) input range.
/**
 * Returns:
 *   true, if futher input required and we have nothing to output
 *   false, otherwise
 * parsed: iterator pointing directly past the parsed and processed part of the input range;
 * read: iterator pointing directly past the last read character of the input range (anything in between [parsed, read) is a prefix of a eom token);
 */
bool smtp_connection::handle_read_data_helper(
        const yconst_buffers_iterator& b,
        const yconst_buffers_iterator& e,
        yconst_buffers_iterator& parsed,
        yconst_buffers_iterator& read)
{
    yconst_buffers_iterator eom;
    bool eom_found = eom_parser_.parse(b, e, eom, read);

    if (g::cfg().m_remove_extra_cr) {
        yconst_buffers_iterator p = b;
        yconst_buffers_iterator crlf_b, crlf_e;
        bool crlf_found = false;
        while (p != eom) {
            crlf_found = crlf_parser_.parse(p, eom, crlf_b, crlf_e);
            if (crlf_found) {
                if (crlf_e - crlf_b > 2) { // \r{2+}\n
                    m_envelope->orig_message_size_ += append(p, crlf_b, m_envelope->orig_message_);        // text preceeding \r+\n token
                    m_envelope->orig_message_size_ += append(crlf_e-2, crlf_e, m_envelope->orig_message_); // \r\n
                    parsed = crlf_e;
                } else {
                    m_envelope->orig_message_size_ += append(p, crlf_e, m_envelope->orig_message_);
                    parsed = crlf_e;
                }
            } else {
                m_envelope->orig_message_size_ += append(p, crlf_b, m_envelope->orig_message_);
                parsed = crlf_b;
            }
            p = crlf_e;
        }
    } else {
        m_envelope->orig_message_size_ += append(b, eom, m_envelope->orig_message_);
        parsed = eom;
    }

    if (eom_found) {
        m_proto_state = STATE_CHECK_DATA;
        io_service_.post(strand_.wrap(bind(&smtp_connection::start_check_data,
                                           shared_from_this())));
        parsed = read;
        return false;
    }

    return true;
}

// Parses and executes commands from [b, e) input range.
/**
 * Returns:
 *   true, if futher input required and we have nothing to output
 *   false, otherwise
 * parsed: iterator pointing directly past the parsed and processed part of the input range;
 * read: iterator pointing directly past the last read character of the input range (anything in between [parsed, read) is a prefix of a command);
*/
bool smtp_connection::handle_read_command_helper(
        const yconst_buffers_iterator& b,
        const yconst_buffers_iterator& e,
        yconst_buffers_iterator& parsed,
        yconst_buffers_iterator& read) {
    if ((read = std::find(b, e, '\n')) == e) {
        return true;
    }

    string command(parsed, read);
    parsed = ++read;

    std::ostream os(&m_response);
    bool res = execute_command(command, os);

    if (res) {
        switch (ssl_state_) {
        case ssl_none:
        case ssl_active:
            send_response(boost::bind(
                &smtp_connection::handle_write_request,
                shared_from_this(),
                boost::asio::placeholders::error));
            break;

        case ssl_hand_shake:
            boost::asio::async_write(socket(), m_response,
                    strand_.wrap(boost::bind(&smtp_connection::handle_ssl_handshake, shared_from_this(),
                                    boost::asio::placeholders::error)));
            break;
        }
    } else {
        send_response(boost::bind(&smtp_connection::handle_last_write_request,
                                  shared_from_this(),
                                  boost::asio::placeholders::error),
                      true);
    }
    return false;
}

// Parses the first size characters of buffers.data().
void smtp_connection::handle_read_helper(std::size_t size)
{
    yconst_buffers bufs = buffers.data();
    yconst_buffers_iterator b = ybuffers_begin(bufs);
    yconst_buffers_iterator e = b + size;

    log(r::log::buffers,
        str(boost::format(">>> %1%") % util::str_cleanup_crlf(string(b, e))));

    yconst_buffers_iterator bb = b + m_envelope->orig_message_token_marker_size_;
    assert (bb < e);

    yconst_buffers_iterator read = bb;
    yconst_buffers_iterator parsed = b;
    bool cont = (m_proto_state == STATE_BLAST_FILE)
            ? handle_read_data_helper(bb, e, parsed, read)
            : handle_read_command_helper(bb, e, parsed, read);

    std::ptrdiff_t parsed_len = parsed - b;
    m_envelope->orig_message_token_marker_size_ = read - parsed;

    buffers.consume(parsed_len);

    if (cont) {
        start_read();
    }
}


void smtp_connection::handle_read(const boost::system::error_code &ec,
                                  size_t size)
{
    read_pending = false;

    if (!ec) {
        if (size == 0) {
            // TODO investigate: is it really happens?
            PDBG("size == 0");

            PDBG("close_status_t::fail");
            close_status = close_status_t::fail;
            m_manager.stop(shared_from_this());
            return;
        }

//        PDBG("size=%zu buffers.size()=%zu", size, buffers.size());
        buffers.commit(size);
//        PDBG("buffers.size()=%zu", buffers.size());
        handle_read_helper(buffers.size());
    } else {
        if (ec != ba::error::operation_aborted) {

            PDBG("read: ec.message()='%s' size=%zu", ec.message().c_str(), size);
            PDBG("state=%s msg_count_mail_from=%u msg_count_sent=%u",
                 get_proto_state_name(m_proto_state),
                 msg_count_mail_from,
                 msg_count_sent);

            if (ec == ba::error::eof && !smtp_client_started) {
                // log for spamhaus if we still hadn't do that
                // clients closed tarpitted sessions are coming here,
                // but they are logged as normal sessions for now
                // TODO maybe log as a bad-behaving session (without client host name)?
                log_spamhaus(m_connected_ip.to_v4().to_string(),
                             m_helo_host,
                             m_remote_host_name);

                log(r::log::notice,
                    str(boost::format("%1%[%2%] REJECT: client closed connection; from=<%3%> tarpit=%4%")
                        % (m_remote_host_name.empty() ? "[UNAVAILABLE]" : m_remote_host_name.c_str())
                        % m_connected_ip.to_v4().to_string()
                        % (m_envelope ? m_envelope->m_sender.c_str() : "")
                        % tarpit));

                PDBG("close_status_t::fail_client_closed_connection");
                close_status = close_status_t::fail_client_closed_connection;
            } else {
                // TODO investigate & rework???
                // this is a workaround for the case when connection is closed before
                // we receive the QUIT command
                // seems that io scheme must be (heavily!!!) reworked
                // use async_read_until() instead of async_read_some() for commands?
                // now don't have a time for this
                if (!(m_proto_state == STATE_HELLO
                      && msg_count_mail_from
                      && msg_count_mail_from == msg_count_sent)) {
                    PDBG("close_status_t::fail");
                    close_status = close_status_t::fail;
                }
            }

            m_manager.stop(shared_from_this());
        }
    }
}


void smtp_connection::start_check_data()
{
    m_timer.cancel();

    m_check_data.m_session_id = m_session_id;
    m_check_data.m_result = check::CHK_ACCEPT;
    m_check_data.m_answer.clear();
    // we will need client IP in the SMTP client for XCLIENT command
    m_check_data.m_remote_ip = m_connected_ip.to_string();
    m_check_data.m_remote_host = m_remote_host_name;
    m_check_data.m_helo_host = m_helo_host;

    if (g::cfg().m_message_size_limit &&
            m_envelope->orig_message_size_ > g::cfg().m_message_size_limit) {
        ++m_error_count;

        m_check_data.m_result = check::CHK_REJECT;
        m_check_data.m_answer =  "552 5.3.4 Message is too big;";

        log(r::log::warning, "message size limit exceeded");

        end_check_data();
    } else {
//        PDBG("call smtp_delivery_start()");
        smtp_delivery_start();
    }
}


namespace {
void handle_parse_header(const header_iterator_range_t &name,
                         const header_iterator_range_t &header,
                         const header_iterator_range_t &value,
                         list<header_iterator_range_t> &h,
                         header_iterator_range_t &message_id,
                         unordered_set<string> &unique_h) {
    string lname;   // lower-cased header name
    lname.reserve(name.size());
    std::transform(name.begin(), name.end(), back_inserter(lname), ::tolower);
    unique_h.insert(lname);

    if (!strcmp(lname.c_str(), "message-id")) {
        message_id = value;
    }

    h.push_back(header);
}
}

void smtp_connection::smtp_delivery_start()
{
	yconst_buffers& orig_m = m_envelope->orig_message_;
	yconst_buffers& alt_m = m_envelope->altered_message_;
	yconst_buffers& orig_h = m_envelope->orig_headers_;
	yconst_buffers& added_h = m_envelope->added_headers_;

	if (m_check_data.m_result != check::CHK_ACCEPT) {
		PDBG("call end_check_data()");
		end_check_data();
		return;
	}

	// alter headers & compose the resulting message here
	typedef list<header_iterator_range_t> hl_t; // header fields subset from the original message for the composed message
	hl_t h;
	header_iterator_range_t message_id;
	unordered_set<string> unique_h;
	header_iterator_range_t::iterator b = ybuffers_begin(orig_m);
	header_iterator_range_t::iterator e = ybuffers_end(orig_m);
	header_iterator_range_t r(b, e);
	m_envelope->orig_message_body_beg_ = parse_header(
		r,
		boost::bind(&handle_parse_header,
				  _1,
				  _2,
				  _3,
				  boost::ref(h),
				  boost::ref(message_id),
				  boost::ref(unique_h)));

	shared_const_chunk crlf(new chunk_csl("\r\n"));
	for(hl_t::const_iterator it=h.begin(); it!=h.end(); ++it) {
		// append existing headers
		append(it->begin(), it->end(), orig_h);
		append(crlf, orig_h);
	}

	// add missing headers
	if (unique_h.find("message-id") == unique_h.end()) {
		time_t rawtime;
		time(&rawtime);
		struct tm timeinfo;
		localtime_r(&rawtime, &timeinfo);
		char timeid[100];
		strftime(timeid, sizeof(timeid), "%Y%m%d%H%M%S", &timeinfo);

		// format: <20100406110540.C671D18D007F@mxback1.mail.yandex.net>
		string message_id_str = str(boost::format("<%1%.%2%@%3%>")
									% timeid
									% m_envelope->m_id
									% boost::asio::ip::host_name());

		append(str(boost::format("Message-Id: %1%\r\n") % message_id_str), added_h);

		log(r::log::info,
			str(boost::format("message-id=%1%") % message_id_str));
	} else {
		log(r::log::info,
			str(boost::format("message-id=%1%") % message_id));
	}

	if (unique_h.find("date") == unique_h.end()) {
		char timestr[256];
		char zonestr[256];
		time_t rawtime;
		time (&rawtime);
		append(str(boost::format("Date: %1%")
				   % rfc822date(&rawtime,
								timestr,
								sizeof(timestr),
								zonestr,
								sizeof(zonestr))),
			   added_h);
	}

	if (unique_h.find("from") == unique_h.end()) {
		append("From: MAILER-DAEMON\r\n", added_h);
	}

	if (unique_h.find("to") == unique_h.end()) {
		append("To: undisclosed-recipients:;\r\n", added_h);
	}

	append(added_h.begin(), added_h.end(), alt_m);
	append(orig_h.begin(), orig_h.end(), alt_m);
	append(crlf, alt_m);
	append(m_envelope->orig_message_body_beg_, ybuffers_end(orig_m), alt_m);

#if 0   // LMTP support is turned off for now
        if (g::cfg().m_use_local_relay) {
            if (m_smtp_client)
                m_smtp_client->stop();
            m_smtp_client.reset(new smtp_client(io_service_, backend_mgr));

            m_smtp_client->start(
                m_check_data,
                strand_.wrap(bind(&smtp_connection::end_lmtp_proto, shared_from_this())),
                m_envelope,
                g::cfg().m_local_relay_host,
                "LOCAL",
                g::cfg().m_dns_servers);
        } else {
            smtp_delivery();
        }
#endif

		smtp_delivery();
}

void smtp_connection::end_lmtp_proto()
{
    m_envelope->remove_delivered_rcpt();
    if (m_envelope->m_rcpt_list.empty()) {
        end_check_data();
    } else {
        smtp_delivery();
    }
}


void smtp_connection::smtp_delivery()
{
    if (m_smtp_client) {
        m_smtp_client->stop();
    }
    m_smtp_client.reset(new smtp_client(io_service_, backend_mgr));

    m_check_data.tarpit = tarpit;
    m_smtp_client->start(
        m_check_data,
        strand_.wrap(bind(&smtp_connection::end_check_data, shared_from_this())),
        *m_envelope,
        g::cfg().dns_ip);
    smtp_client_started = true;
}


void smtp_connection::end_check_data() {
    if (m_smtp_client) {
        m_check_data = m_smtp_client->check_data();
        m_smtp_client->stop();
    }
    m_smtp_client.reset();

    m_proto_state = STATE_HELLO;

    std::ostream response_stream(&m_response);

    switch (m_check_data.m_result) {
        case check::CHK_ACCEPT:
        case check::CHK_DISCARD:
            ++msg_count_sent;
            g::mon().on_mail_delivered();
//            PDBG("close_status_t::ok");
            close_status = close_status_t::ok;
            response_stream << "250 2.0.0 Ok: queued on " << boost::asio::ip::host_name() << " as";
            break;

        case check::CHK_REJECT:
//            PDBG("close_status_t::fail");
            close_status = close_status_t::fail;
            if (!m_check_data.m_answer.empty()) {
                response_stream << m_check_data.m_answer;
            } else {
                response_stream << "550 " << boost::asio::ip::host_name();
            }
            break;

        case check::CHK_TEMPFAIL:
//            PDBG("close_status_t::fail");
            close_status = close_status_t::fail;
            if (!m_check_data.m_answer.empty()) {
                response_stream << m_check_data.m_answer;
            } else {
                response_stream << "451 4.7.1 Service unavailable - try again later";
            }
            break;
    }

    response_stream << ' ' << m_session_id << '-' << m_envelope->m_id << "\r\n";

    // don't tarpit after receiving '.' from client
    send_response(boost::bind(&smtp_connection::handle_write_request,
                              shared_from_this(),
                              boost::asio::placeholders::error),
                  true);
}


void smtp_connection::send_response(
        boost::function<void(const boost::system::error_code &)> handler,
        bool force_do_not_tarpit)
{
    if (m_response.size() == 0) {
        PDBG("nothing to send");
        return;
    }

    if (force_do_not_tarpit
            || g::get_stop_flag()   // gracefully stop
            || is_whitelisted
            || g::cfg().m_tarpit_delay_seconds == 0) {
        // send immediately
        send_response2(boost::system::error_code(), handler);
        return;
    }

    // send with tarpit timeout
    m_tarpit_timer.expires_from_now(
        boost::posix_time::seconds(g::cfg().m_tarpit_delay_seconds));
    m_tarpit_timer.async_wait(strand_.wrap(
        boost::bind(&smtp_connection::send_response2,
                    shared_from_this(),
                    boost::asio::placeholders::error,
                    handler)));
}


void smtp_connection::send_response2(
        const boost::system::error_code &ec,
        boost::function<void(const boost::system::error_code &)> handler)
{
    if (ec) {   // tarpit timer was canceled in stop()
        return;
    }

    // check that the client hasn't sent something before receiving greeting msg
    // don't check whitelisted hosts
    if (!is_whitelisted
            && g::cfg().m_socket_check
            && m_proto_state == STATE_START) {
        bool empty;
        try {
            empty = check_socket_read_buffer_is_empty();
        } catch (const bs::system_error &e) {
            // TODO this log remove when finished investigating the cause
            // client quickly closed the connection by itself?
            PLOG(r::log::crit,
                 "EXCEPTION: check_socket_read_buffer_is_empty '%s'",
                 e.code().message().c_str());

            PDBG("close_status_t::fail");
            close_status = close_status_t::fail;
            m_manager.stop(shared_from_this());
            return;
        }

        if (!empty) {
            // log for spamhaus if we still hadn't do that
            // log as a bad behaving session (without client host name)
            log_spamhaus(m_connected_ip.to_v4().to_string(),
                         string(),
                         string());

            log(r::log::notice,
                str(boost::format("%1%[%2%] REJECT: client wrote to socket before greeting; tarpit=%3%")
                    % (m_remote_host_name.empty() ? "[UNAVAILABLE]" : m_remote_host_name.c_str())
                    % m_connected_ip.to_v4().to_string()
                    % tarpit));

            PDBG("close_status_t::fail_client_early_write");
            close_status = close_status_t::fail_client_early_write;

            // don't kick off, gracefully close the session instead

            std::ostream response_stream(&m_response);
            response_stream << "554 5.7.1 Service unavailable\r\n";

            // substitute the handler with handle_last_write_request()
            handler = boost::bind(
                        &smtp_connection::handle_last_write_request,
                        shared_from_this(),
                        boost::asio::placeholders::error);
        }
    }

	log(r::log::buffers,
		str(boost::format("<<< %1%")
			% util::str_cleanup_crlf(util::str_from_buf(m_response))));
	if(ssl_state_ == ssl_active) {
        ba::async_write(
            m_ssl_socket,
            m_response,
            strand_.wrap(boost::bind(handler, boost::asio::placeholders::error)));
    } else {
        ba::async_write(
            socket(),
            m_response,
            strand_.wrap(boost::bind(handler, boost::asio::placeholders::error)));
    }
}


void smtp_connection::handle_write_request(const bs::error_code &ec)
{
    if (!ec) {
        if (m_error_count > g::cfg().m_hard_error_limit) {
            log(r::log::crit, "too many errors");

            std::ostream response_stream(&m_response);
            response_stream << "421 4.7.0 " << boost::asio::ip::host_name() << " Error: too many errors\r\n";
            boost::asio::async_write(socket(), m_response,
                    strand_.wrap(boost::bind(&smtp_connection::handle_last_write_request, shared_from_this(),
                                    boost::asio::placeholders::error)));
            return;
        }
        start_read();
    } else {
        if (ec != ba::error::operation_aborted) {
            PDBG("write: ec.message()='%s'", ec.message().c_str());
            PDBG("close_status_t::fail");
            close_status = close_status_t::fail;
            m_manager.stop(shared_from_this());
        }
    }
}

void smtp_connection::handle_last_write_request(
        const boost::system::error_code &ec)
{
#if 0
    // socket will be closed in stop()
    if (!ec) {
        try {
            socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
            socket().close();
        } catch (...) {}
    }
#endif
    if (ec != boost::asio::error::operation_aborted) {
        if (ec) {
            PDBG("close_status_t::fail");
            close_status = close_status_t::fail;
        }
        m_manager.stop(shared_from_this());
    }
}


void smtp_connection::handle_ssl_handshake(const boost::system::error_code& ec)
{
    if (!ec) {
        ssl_state_ = ssl_active;
        m_ssl_socket.async_handshake(boost::asio::ssl::stream_base::server,
                strand_.wrap(boost::bind(&smtp_connection::handle_write_request, shared_from_this(),
                                boost::asio::placeholders::error)));
    } else {
        if (ec != boost::asio::error::operation_aborted) {
            PDBG("close_status_t::fail");
            close_status = close_status_t::fail;
            m_manager.stop(shared_from_this());
        }
    }
}


bool smtp_connection::execute_command(string cmd, std::ostream &os)
{
//    log(MSG_DEBUG,
//        str(boost::format("execute command: '%1%'")
//            % util::str_cleanup_crlf(cmd)));

    // trim starting whitespace
    string::size_type pos = cmd.find_first_not_of( " \t" );
    if (pos != std::string::npos) {
        cmd.erase(0, pos);
    }
    // trim trailing whitespace
    pos = cmd.find_last_not_of( " \t\r\n" );
    if (pos != string::npos) {
        cmd.resize(pos + 1);
    }

    // Split line into command and argument parts
    string arg;
    pos = cmd.find(' ');
    if (pos != string::npos) {
        arg = cmd.substr(pos + 1);
        cmd.resize(pos);
    }

    std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

    auto func = smtp_command_handlers.find(cmd);
    if (func != smtp_command_handlers.cend()) {
        return (func->second)(this, arg, os);
    } else {
        ++m_error_count;
        os << "502 5.5.2 Syntax error, command unrecognized.\r\n";
    }

    return true;
}


bool smtp_connection::smtp_quit( const std::string& _cmd, std::ostream &_response )
{
    _response << "221 2.0.0 Closing connection.\r\n";
    return false;
}

bool smtp_connection::smtp_noop ( const std::string& _cmd, std::ostream &_response )
{
    _response << "250 2.0.0 Ok\r\n";
    return true;
}


bool smtp_connection::smtp_starttls(const string &, std::ostream &response)
{
    // "starttls" is available only for initially unencrypted connections if TLS support is enabled in config
    if (g::cfg().m_use_tls && !m_force_ssl) {
        ssl_state_ = ssl_hand_shake;
        response << "220 Go ahead\r\n";
    } else {
        response << "502 5.5.2 Syntax error, command unrecognized.\r\n";
    }
    return true;
}


bool smtp_connection::smtp_rset(const string &, std::ostream &response)
{
    if (m_proto_state > STATE_START) {
        m_proto_state = STATE_HELLO;
    }
    m_envelope.reset(new envelope(false));
    response << "250 2.0.0 Ok\r\n";
    return true;
}


bool smtp_connection::smtp_helo(const string &cmd, std::ostream &response)
{
    if (!cmd.empty()) {
        m_helo_host = cmd;
        // now we know HELO string, log well-behaved session for spamhaus
        log_spamhaus(m_connected_ip.to_v4().to_string(),
                     m_helo_host,
                     m_remote_host_name);
        response << "250 " << boost::asio::ip::host_name() << "\r\n";
        m_ehlo = false;
        m_proto_state = STATE_HELLO;
    } else {
        // log bad session for spamhaus
        log_spamhaus(m_connected_ip.to_v4().to_string(),
                     m_helo_host,
                     string());
        ++m_error_count;
        response << "501 5.5.4 HELO requires domain address.\r\n";
        m_proto_state = STATE_START;
    }
    return true;
}


bool smtp_connection::smtp_ehlo(const string &cmd, std::ostream &response)
{
    if (!cmd.empty()) {
        m_helo_host = cmd;
        // now we know HELO string, log well-behaved session for spamhaus
        log_spamhaus(m_connected_ip.to_v4().to_string(),
                     m_helo_host,
                     m_remote_host_name);

        response << "250-" << boost::asio::ip::host_name()
                 << "\r\n250-8BITMIME\r\n250-PIPELINING\r\n";
        if (g::cfg().m_message_size_limit > 0) {
            response << "250-SIZE " << g::cfg().m_message_size_limit << "\r\n";
        }
        if (g::cfg().m_use_tls && !m_force_ssl) {
            response << "250-STARTTLS\r\n";
        }
        response << "250 ENHANCEDSTATUSCODES\r\n";

        m_ehlo = true;
        m_proto_state = STATE_HELLO;
    } else {
        // log bad session for spamhaus
        log_spamhaus(m_connected_ip.to_v4().to_string(),
                     m_helo_host,
                     string());
        ++m_error_count;
        response << "501 5.5.4 EHLO requires domain address.\r\n";
        m_proto_state = STATE_START;
    }

    return true;
}

namespace {
string extract_addr(string s) {
    string::size_type beg = s.find("<");
    if (beg != string::npos) {
        string::size_type end = s.find(">", beg);
        if (end != string::npos) {
            return s.substr(beg + 1, end - beg - 1);
        }
    }
    return s;
}

bool is_invalid(char _elem) {
    return !((_elem >= 'a' && _elem <='z') || (_elem >= 'A' && _elem <='Z') ||
            (_elem >= '0' && _elem <='9') || _elem == '-' || _elem =='.' ||
            _elem == '_' || _elem == '@' || _elem == '%' || _elem == '+' ||
            _elem == '=' || _elem == '!' || _elem == '#' ||   _elem == '$' ||
            _elem == '"' ||   _elem == '*' ||   _elem == '-' || _elem == '/' ||
            _elem == '?' ||   _elem == '^' ||   _elem == '`' || _elem == '{' ||
            _elem == '}' ||   _elem == '|' ||   _elem == '~' || _elem == '&'
             ) ;
}
}


bool smtp_connection::smtp_rcpt(const string &_cmd,
                                std::ostream &_response)
{
    if (m_proto_state != STATE_AFTER_MAIL && m_proto_state != STATE_RCPT_OK) {
        PDBG("m_proto_state = %d", m_proto_state);
        ++m_error_count;
        _response << "503 5.5.4 Bad sequence of commands.\r\n";
        return true;
    }

    if (strncasecmp( _cmd.c_str(), "to:", 3 ) != 0) {
        ++m_error_count;
        _response << "501 5.5.4 Wrong param.\r\n";
        return true;
    }

    if (m_envelope->m_rcpt_list.size() >= m_max_rcpt_count) {
        ++m_error_count;
        _response << "452 4.5.3 Error: too many recipients\r\n";
        return true;
    }

    string addr(util::trim(extract_addr(util::trim(_cmd.substr(3)))));

    if (addr.empty()) {
        ++m_error_count;
        _response << "501 5.1.3 Bad recipient address syntax.\r\n";
        return true;
    }

    std::string::size_type dog_pos = addr.find("@");
    if (dog_pos == std::string::npos) {
        ++m_error_count;
        _response << "504 5.5.2 Recipient address rejected: need fully-qualified address\r\n";
        return true;
    }

    if (std::count_if(addr.begin(), addr.end(), is_invalid) > 0) {
        ++m_error_count;
        _response << "501 5.1.3 Bad recipient address syntax.\r\n";
        return true;
    }

#if 0 // original NwSMTP code; seems not correct
    if (addr.find("%") != std::string::npos) {
        ++m_error_count;
        _response << "501 5.1.3 Bad recipient address syntax.\r\n";
        return true;
    }
#endif

    _response << "250 2.1.5 <" << addr << "> recipient ok\r\n";
    m_envelope->add_recipient(std::move(addr));
    m_proto_state = STATE_RCPT_OK;
    return true;
}


bool smtp_connection::smtp_mail(const string &_cmd,
                                std::ostream &_response)
{
    if (strncasecmp(_cmd.c_str(), "from:", 5) != 0) {
        ++m_error_count;
        _response << "501 5.5.4 Syntax: MAIL FROM:<address>\r\n";
        return true;
    }

    if (m_proto_state == STATE_START) {
        ++m_error_count;
        _response << "503 5.5.4 Good girl is greeting first.\r\n";
        return true;
    }

    param_parser::params_map pmap;
    string addr;
    param_parser::parse(_cmd.substr(5), addr, pmap);
    addr = util::trim(extract_addr(addr));

    if (std::count_if(addr.begin(), addr.end(), is_invalid) > 0) {
        ++m_error_count;
        _response << "501 5.1.7 Bad address mailbox syntax.\r\n";
        return true;
    }

    // now we have 'from' address on hands and can reject blacklisted connection
    if (is_blacklisted) {
        // log bad session for spamhaus
        log_spamhaus(m_connected_ip.to_v4().to_string(),
                     m_helo_host,
                     string());
        log(r::log::notice,
            str(boost::format("%1%[%2%] REJECT: blacklisted (%3%) from=<%4%>")
                % (m_remote_host_name.empty() ? "[UNAVAILABLE]" : m_remote_host_name.c_str())
                % m_connected_ip.to_v4().to_string()
                % bl_status_str
                % addr));
        _response << "554 5.7.1 Client host blocked\r\n";
        return false;
    }

    if (g::cfg().m_message_size_limit > 0) {
        uint32_t msize = atoi(pmap["size"].c_str());
        if (msize > g::cfg().m_message_size_limit) {
            ++m_error_count;
            _response << "552 5.3.4 Message size exceeds fixed limit.\r\n";
            return true;
        }
    }

    _response << "250 2.1.0 <" << addr << "> ok\r\n";

    m_envelope.reset(new envelope(true));

#if 0 // it was original NwSMTP code; seems that it's not needed
    m_envelope->m_sender = addr.empty() ? string("<>") : std::move(addr);
#else
    m_envelope->m_sender = std::move(addr);
#endif

    ++msg_count_mail_from;
    g::mon().on_mail_rcpt_to();

    m_proto_state = STATE_AFTER_MAIL;
    return true;
}


bool smtp_connection::smtp_data(const string &_cmd, std::ostream &_response)
{
    if (m_proto_state != STATE_RCPT_OK) {
//        PDBG("m_proto_state = %d", m_proto_state);
        ++m_error_count;
        _response << "503 5.5.4 Bad sequence of commands.\r\n";
        return true;
    }

    if (m_envelope->m_rcpt_list.empty()) {
        m_error_count++;
        _response << "503 5.5.4 No correct recipients.\r\n";
        return true;
    }

    _response << "354 Enter mail, end with \".\" on a line by itself\r\n";

    m_proto_state = STATE_BLAST_FILE;
    m_timer_value = g::cfg().frontend_data_timeout;
    m_envelope->orig_message_size_ = 0;

    time_t now;
    time(&now);

    append(str(boost::format("Received: from %1% (%1% [%2%])\r\n\tby %3% (resmtp/Rambler) with %4% id %5%;\r\n\t%6%\r\n")
               % (m_remote_host_name.empty() ? "UNKNOWN" : m_remote_host_name.c_str())
               % m_connected_ip.to_string()
               % boost::asio::ip::host_name()
               % (m_ehlo ? "ESMTP": "SMTP")
               % m_envelope->m_id
               % mail_date(now)),
           m_envelope->added_headers_);

//    append(str( boost::format("X-Yandex-Front: %1%\r\n")
//                % boost::asio::ip::host_name()
//                ),
//            m_envelope->added_headers_);

//    append(str( boost::format("X-Yandex-TimeMark: %1%\r\n")
//                    % now
//                ),
//            m_envelope->added_headers_);

    return true;
}

void smtp_connection::stop()
{
	m_timer.cancel();
	m_tarpit_timer.cancel();

	m_resolver.cancel();

    m_proto_state = STATE_START;

    try {
        socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
        socket().close();
    } catch (...) {}

    if (m_dnsbl_check) {
        m_dnsbl_check->stop();
        m_dnsbl_check.reset();
    }

    if (m_dnswl_check) {
        m_dnswl_check->stop();
        m_dnswl_check.reset();
    }

    if (m_smtp_client) {
        m_smtp_client->stop();
        // timer handlers in smtp_client are called after returning from stop()
#if 0
        m_smtp_client.reset();
#endif
    }

    on_connection_close();
}


void smtp_connection::handle_timer(const boost::system::error_code &ec)
{
    if (ec) {   // timer was canceled in stop()
        return;
    }

    PDBG("close_status_t::fail");
    close_status = close_status_t::fail;

    std::ostream response_stream(&m_response);
    response_stream << "421 4.4.2 "
                    << boost::asio::ip::host_name()
                    << " Error: timeout exceeded\r\n";

    if (m_proto_state == STATE_BLAST_FILE) {
        log(r::log::debug,
            str(boost::format("timeout after DATA (%1% bytes) from %2%[%3%]")
                % buffers.size()
                % (m_remote_host_name.empty() ? "[UNAVAILABLE]" : m_remote_host_name.c_str())
                % m_connected_ip.to_string()));
    } else {
        const char *state_desc = "";
        switch (m_proto_state)
        {
        case STATE_START:
            state_desc = "START";
            break;
        case STATE_AFTER_MAIL:
            state_desc = "MAIL FROM";
            break;
        case STATE_RCPT_OK:
            state_desc = "RCPT TO";
            break;
        case STATE_HELLO:
        default:
            state_desc = "HELO";
            break;
        }
        log(r::log::debug,
            str(boost::format("timeout after %1% from %2%[%3%]")
                % state_desc
                % (m_remote_host_name.empty() ? "[UNAVAILABLE]" : m_remote_host_name.c_str())
                % m_connected_ip.to_string()));
    }

    log(r::log::notice,
        str(boost::format("%1%[%2%] REJECT: timeout; from=<%3%> tarpit=%4%")
            % (m_remote_host_name.empty() ? "[UNAVAILABLE]" : m_remote_host_name.c_str())
            % m_connected_ip.to_v4().to_string()
            % (m_envelope ? m_envelope->m_sender.c_str() : "")
            % tarpit));

    send_response(boost::bind(&smtp_connection::handle_last_write_request,
                              shared_from_this(),
                              boost::asio::placeholders::error),
                  true);
}


void smtp_connection::restart_timeout()
{
    m_timer.expires_from_now(boost::posix_time::seconds(m_timer_value));
    m_timer.async_wait(
        strand_.wrap(boost::bind(&smtp_connection::handle_timer,
                        shared_from_this(), boost::asio::placeholders::error)));
}


void smtp_connection::log(r::log prio, const string &msg) noexcept
{
    g::log().msg(prio,
              str(boost::format("%1%-%2%-FRONT: %3%")
                  % m_session_id
                  % m_envelope->m_id
                  % msg));
}


const char * smtp_connection::get_proto_state_name(proto_state_t st)
{
    switch (st) {
    case STATE_START:
        return "START";
    case STATE_HELLO:
        return "HELLO";
    case STATE_AFTER_MAIL:
        return "AFTER_MAIL";
    case STATE_RCPT_OK:
        return "RCPT_OK";
    case STATE_BLAST_FILE:
        return "BLAST_FILE";
    case STATE_CHECK_DATA:
        return "CHECK_DATA";
    }
    assert(false && "update the switch() above");
    return nullptr;
}


void smtp_connection::log_spamhaus(
        const string &client_host_address,
        const string &helo,
        const string &client_host_name)
{
    if (g::cfg().spamhaus_log_file.empty()) return;

    if (!spamhaus_log_pending) return;

    if (client_host_name.empty()) {
        g::logsph().msg(str(boost::format("%1% %2% %3%")
            % client_host_address
            % (!helo.empty() ? helo : client_host_address)
            % time(nullptr)));
    } else {
        g::logsph().msg(str(boost::format("%1% %2% %3% %4%")
            % client_host_address
            % (!helo.empty() ? helo : client_host_address)
            % time(nullptr)
            % client_host_name));
    }

    spamhaus_log_pending = false;
}
