#include "smtp_connection_manager.h"

#include <algorithm>
#include <cassert>

#include <boost/bind.hpp>
#include <boost/format.hpp>

#include "log.h"


using namespace std;


smtp_connection_manager::smtp_connection_manager(
        uint32_t max_sess,
        uint32_t max_sess_per_ip)
    : max_sessions(max_sess)
    , max_sessions_per_ip(max_sess_per_ip)
{
    m_sessions.reserve(max(max_sessions, RESERVE_SIZE));
    m_ip_count.reserve(max(max_sessions, RESERVE_SIZE));
}


bool smtp_connection_manager::start(
        smtp_connection_ptr session,
        std::string &msg)
{
    boost::mutex::scoped_lock lock(m_mutex);

    if (max_sessions && m_sessions.size() >= max_sessions) {
        msg = str(boost::format("421 4.7.0 %1% Error: too many connections.\r\n")
                  % boost::asio::ip::host_name());
        return false;
    }

    if (max_sessions_per_ip && get_ip_count(session->remote_address()) >= max_sessions_per_ip) {
        msg = str(boost::format("421 4.7.0 %1% Error: too many connections from %2%\r\n")
                  % boost::asio::ip::host_name()
                  % session->remote_address().to_string());
        return false;
    }

    m_sessions.insert(session);
    ip_count_inc(session->remote_address());

    return true;
}


void smtp_connection_manager::stop(smtp_connection_ptr session)
{
    {
        boost::mutex::scoped_lock lock(m_mutex);
        auto it = m_sessions.find(session);
        if (it != m_sessions.end()) {
            m_sessions.erase(it);
            ip_count_dec(session->remote_address());
        }
    }
    // now we can slowly stop the session
    session->stop();
}


void smtp_connection_manager::stop_all()
{
    boost::mutex::scoped_lock lock(m_mutex);

    // clear sessions and IP counters
    decltype(m_sessions) tmp;
    tmp.swap(m_sessions);
    m_sessions.reserve(max(max_sessions, RESERVE_SIZE));   // for possible further usage
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
        m_ip_count.insert(per_ip_session_t::value_type(addr.to_v4().to_ulong(), 1));
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
