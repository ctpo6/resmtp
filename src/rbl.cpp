#include "rbl.h"

#include <iostream>
#include <utility>

#include <boost/bind.hpp>
#include <boost/format.hpp>

#include "global.h"
#include "util.h"


using namespace std;
using namespace y::net;

namespace ba = boost::asio;
namespace bs = boost::system;


rbl_check::rbl_check(ba::io_service& _io_service)
    : m_resolver(_io_service)
{
}


void rbl_check::add_rbl_source(string host_name)
{
    m_source_list.push_back(std::move(host_name));
}


void rbl_check::start(const ba::ip::address_v4 &address, complete_cb cb)
{
    m_message.clear();

    if (m_source_list.empty()) {
        m_resolver.get_io_service().post(cb);
        return;
    }

    m_address = address;
    m_complete = cb;
    m_current_source = m_source_list.begin();
    start_resolve(m_address, *m_current_source);
}


void rbl_check::start_resolve(const ba::ip::address_v4 &address,
                              const string &rbl_host)
{
//    PDBG("ENTER %s %s", av4.to_string().c_str(), d.c_str());
    m_resolver.async_resolve(
        util::rev_order_av4_str(address, rbl_host),
        dns::type_a,
        boost::bind(&rbl_check::handle_resolve,
                    shared_from_this(),
                    ba::placeholders::error,
                    ba::placeholders::iterator));
}


void rbl_check::handle_resolve(const boost::system::error_code &ec,
                               dns::resolver::iterator it)
{
    if (!ec) {
        if (m_complete) {
            m_message = str(boost::format("%1% (%2%)")
                % *m_current_source
                % boost::dynamic_pointer_cast<dns::a_resource>(*it)->address().to_string());
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
