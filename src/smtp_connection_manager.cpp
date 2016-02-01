#include "smtp_connection_manager.h"

#include <algorithm>
#include <cassert>

#include <boost/bind.hpp>
#include <boost/format.hpp>

#include "global.h"


using namespace std;


const uint32_t smtp_connection_manager::RESERVE_SIZE = 100000;


smtp_connection_manager::smtp_connection_manager(
        uint32_t max_sess,
        uint32_t max_sess_per_ip)
    : max_sessions(max_sess)
    , max_sessions_per_ip(max_sess_per_ip)
{
    connections.reserve(max(max_sessions, RESERVE_SIZE));
    m_ip_count.reserve(max(max_sessions, RESERVE_SIZE));
}


bool smtp_connection_manager::start(smtp_connection_ptr session,
                                    string &msg)
{
    boost::mutex::scoped_lock lock(m_mutex);

    if (max_sessions &&
            connections.size() >= max_sessions) {
        msg.assign("421 4.7.0 Too many connections\r\n");
        return false;
    }

    if (max_sessions_per_ip &&
            get_ip_count(session->remote_address()) >= max_sessions_per_ip) {
        msg = str(boost::format("421 4.7.0 Too many connections from %1%\r\n")
                  % session->remote_address().to_string());
        return false;
    }

    connections.insert(session);
    ip_count_inc(session->remote_address());

    return true;
}


void smtp_connection_manager::stop(smtp_connection_ptr conn)
{
    {
        boost::mutex::scoped_lock lock(m_mutex);
        auto it = connections.find(conn);
        if (it != connections.end()) {
            connections.erase(it);
            ip_count_dec(conn->remote_address());
        }
    }
    // now we can slowly stop the session
    conn->stop();
}


void smtp_connection_manager::stop_all()
{
    boost::mutex::scoped_lock lock(m_mutex);

    // clear sessions and IP counters
    decltype(connections) tmp;
    tmp.swap(connections);
    connections.reserve(max(max_sessions, RESERVE_SIZE));   // for possible further usage
    m_ip_count.clear();

    lock.unlock();

    // now we can slowly stop sessions
    for(auto &s: tmp) {
        s->stop();
    }
}


uint32_t smtp_connection_manager::ip_count_inc(
        const boost::asio::ip::address &addr) {
    auto it = m_ip_count.find(addr.to_v4().to_ulong());
    if (it == m_ip_count.end()) {
        m_ip_count.insert(ip_connection_map_t::value_type(addr.to_v4().to_ulong(), 1));
        return 1;
    }
    return ++(it->second);
}


uint32_t smtp_connection_manager::ip_count_dec(
        const boost::asio::ip::address &addr)
{
    auto it = m_ip_count.find(addr.to_v4().to_ulong());
    assert(it != m_ip_count.end()
            && it->second != 0
            && "error in IP count decrement logic");
    uint32_t r = --(it->second);
    if (!r) {
        m_ip_count.erase(it);
    }
    return r;
}


uint32_t smtp_connection_manager::get_ip_count(
        const boost::asio::ip::address &addr) const
{
    auto it = m_ip_count.find(addr.to_v4().to_ulong());
    return it != m_ip_count.end() ? it->second : 0;
}
