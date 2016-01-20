#ifndef _RBL_H_
#define _RBL_H_

#include <functional>
#include <list>
#include <memory>
#include <string>

#include <boost/asio.hpp>
#include <boost/noncopyable.hpp>

#include <net/dns_resolver.hpp>


using std::list;
using std::string;


class rbl_check:
        public std::enable_shared_from_this<rbl_check>,
        private boost::noncopyable {
public:
    typedef std::function<void ()> complete_cb;

    rbl_check(boost::asio::io_service &io_service);

    void add_nameserver(const boost::asio::ip::address &addr)
    {
        m_resolver.add_nameserver(addr);
    }

    void add_rbl_source(string host_name); // Add rbl source host

    void start(const boost::asio::ip::address_v4 &address,
               complete_cb cb);
    void stop();


    // -------------------------------------------------------------------------
    // these getters must be called only once
    // that's what is needed in the code now

    // true - blacklisted
    bool get_status(string &s)
    {
        s.swap(m_message);
        return !s.empty();
    }

    string get_status()
    {
        string s;
        s.swap(m_message);
        return s;
    }
    // -------------------------------------------------------------------------

private:

    void handle_resolve(const boost::system::error_code &ec,
                        y::net::dns::resolver::iterator it);

    void start_resolve(const boost::asio::ip::address_v4 &address,
                       const std::string &rbl_host);

    list<string> m_source_list;
    list<string>::iterator m_current_source;

    y::net::dns::resolver m_resolver;

    boost::asio::ip::address_v4 m_address;

    complete_cb m_complete;

    string m_message;
};

typedef std::shared_ptr<rbl_check> rbl_client_ptr;

#endif // _RBL_H_
