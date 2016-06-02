#ifndef _SMTP_CONNECTION_MANAGER_H_
#define _SMTP_CONNECTION_MANAGER_H_

#include <atomic>
#include <ostream>
#include <set>
#include <string>
#include <unordered_map>

#if 0
#include <boost/asio.hpp>
#else
#include "asio/asio.hpp"
#endif
#include <boost/noncopyable.hpp>

#include "smtp_connection.h"


class smtp_connection_manager : private boost::noncopyable
{
public:
    smtp_connection_manager(uint32_t max_sess,
                            uint32_t max_sess_per_ip,
                            uint32_t n_sessions_quit_after);

    // called by server on connection accept
    void start(smtp_connection_ptr conn, bool force_ssl);

    // called by conn itself
    void stop(smtp_connection_ptr conn);

    void stop_all();

    void print_status_info(std::ostream &os);
    
protected:

    // see *.cpp for value
    // couldn't place it here due to ld error
    static const uint32_t RESERVE_SIZE;

    const uint32_t max_sessions;
    const uint32_t max_sessions_per_ip;
    const uint32_t n_sessions_quit_after_;

    std::atomic<uint32_t> session_count_;
    
    std::set<smtp_connection_ptr> connections;

    // pairs: IPv4 (as uint32_t) -> count of sessions
    typedef std::unordered_map<uint32_t, uint32_t> ip_connection_map_t;
    ip_connection_map_t m_ip_count;

    uint32_t ip_count_inc(const asio::ip::address &addr);
    uint32_t ip_count_dec(const asio::ip::address &addr);
    uint32_t get_ip_count(const asio::ip::address &addr) const;

    boost::mutex m_mutex;
};

#endif
