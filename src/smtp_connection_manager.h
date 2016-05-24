#ifndef _SMTP_CONNECTION_MANAGER_H_
#define _SMTP_CONNECTION_MANAGER_H_

#include <set>
#include <string>
#include <unordered_map>

#include <boost/asio.hpp>
#include <boost/noncopyable.hpp>

#include "smtp_connection.h"


class smtp_connection_manager : private boost::noncopyable
{
public:
    smtp_connection_manager(uint32_t max_sess, uint32_t max_sess_per_ip);

    // error_msg - returned on fail
    bool start(smtp_connection_ptr session, std::string &error_msg);

    // called by conn itself
    void stop(smtp_connection_ptr conn);

    void stop_all();

protected:

    // see *.cpp for value
    // couldn't place it here due to ld error
    static const uint32_t RESERVE_SIZE;

    const uint32_t max_sessions;
    const uint32_t max_sessions_per_ip;

    std::set<smtp_connection_ptr> connections;

    // pairs: IPv4 (as uint32_t) -> count of sessions
    typedef std::unordered_map<uint32_t, uint32_t> ip_connection_map_t;
    ip_connection_map_t m_ip_count;

    uint32_t ip_count_inc(const boost::asio::ip::address &addr);
    uint32_t ip_count_dec(const boost::asio::ip::address &addr);
    uint32_t get_ip_count(const boost::asio::ip::address &addr) const;

    boost::mutex m_mutex;
};

#endif
