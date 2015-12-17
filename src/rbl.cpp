#include "rbl.h"

#include <iostream>

#include <boost/bind.hpp>
#include <boost/format.hpp>

#include "log.h"
#include "util.h"

using namespace std;
using namespace y::net;


rbl_check::rbl_check(boost::asio::io_service& _io_service)
    : m_resolver(_io_service)
{
}


void rbl_check::add_rbl_source(string host_name)
{
    m_source_list.push_back(host_name);
}


void rbl_check::start(const boost::asio::ip::address_v4 &_address, complete_cb _callback)
{
    m_complete = _callback;

    if (m_source_list.empty()) {
        m_message.clear();
        m_resolver.get_io_service().post(m_complete);
        return;
    }

    m_current_source = m_source_list.begin();

    m_address = _address;

    start_resolve(m_address, *m_current_source);
}


void rbl_check::start_resolve(const boost::asio::ip::address_v4& av4, const std::string& d)
{
//    PDBG("ENTER %s %s", av4.to_string().c_str(), d.c_str());
    m_resolver.async_resolve(
        util::rev_order_av4_str(av4, d),
        dns::type_a,
        boost::bind(&rbl_check::handle_resolve, shared_from_this(), _1, _2));
}


void rbl_check::handle_resolve(const boost::system::error_code& ec,
                               dns::resolver::iterator)
{
    if (!ec) {
        if (m_complete) {
            m_message = string("554 5.7.1 Service unavailable\r\n");
            m_resolver.get_io_service().post(m_complete);
            m_complete = nullptr;
        }
    } else {
        if (++m_current_source == m_source_list.end()) {
            if (m_complete) {
                m_message.clear();
                m_resolver.get_io_service().post(m_complete);
                m_complete = nullptr;
            }
        } else {
            start_resolve(m_address, *m_current_source);
        }
    }
}


void rbl_check::stop()
{
    m_resolver.cancel();
}


bool rbl_check::get_status(std::string &_message)
{
    _message = m_message;
    return !m_message.empty();
}
