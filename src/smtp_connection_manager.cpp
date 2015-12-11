#include "smtp_connection_manager.h"

#include <boost/bind.hpp>
#include <boost/format.hpp>

#include "log.h"


smtp_connection_manager::smtp_connection_manager(
        uint32_t max_sess,
        uint32_t max_sess_per_ip)
    : max_sessions(max_sess)
    , max_sessions_per_ip(max_sess_per_ip)
{
}


bool smtp_connection_manager::start(
        smtp_connection_ptr _session,
        std::string &_msg)
{
    boost::mutex::scoped_lock lck(m_mutex);

    if (m_sessions.size() >= max_sessions) {
        _msg = str(boost::format("421 4.7.0 %1% Error: too many connections.\r\n")
                   % boost::asio::ip::host_name());
        return false;
    }

    if (get_ip_session(_session->remote_address()) >= max_sessions_per_ip) {
        _msg = str(boost::format("421 4.7.0 %1% Error: too many connections from %2%\r\n")
                   % boost::asio::ip::host_name()
                   % _session->remote_address().to_string());
        return false;
    }

    m_sessions.insert(_session);
    ip_inc(_session->remote_address());

    return true;
}


void smtp_connection_manager::stop(smtp_connection_ptr _session)
{
    boost::mutex::scoped_lock lck(m_mutex);

    auto sessit = m_sessions.find(_session);
    if (sessit != m_sessions.end()) {
        m_sessions.erase(sessit);
        ip_dec(_session->remote_address());
        lck.unlock();
    }

    _session->stop();
}


void smtp_connection_manager::stop_all() {
    for(auto &s: m_sessions) {
        s->stop();
    }
    m_sessions.clear();
}


unsigned int smtp_connection_manager::ip_inc(const boost::asio::ip::address _address) {
    auto it = m_ip_count.find(_address.to_v4().to_ulong());
    if (it == m_ip_count.end()) {
        m_ip_count.insert(per_ip_session_t::value_type(_address.to_v4().to_ulong(), 1));
        return 1;
    }
    return ++(it->second);
}


unsigned int smtp_connection_manager::ip_dec(const boost::asio::ip::address _address) {
    auto it = m_ip_count.find(_address.to_v4().to_ulong());
    if (it != m_ip_count.end()) {
        if (it->second) {
            --(it->second);
        } else {
            m_ip_count.erase(it);
        }
        return it->second;
    }
    return 0;
}


unsigned int smtp_connection_manager::get_ip_session(const boost::asio::ip::address _address) {
    auto it = m_ip_count.find(_address.to_v4().to_ulong());
    return it != m_ip_count.end() ? it->second : 0;
}
