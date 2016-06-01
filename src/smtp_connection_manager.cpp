#include "smtp_connection_manager.h"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <utility>

#include <boost/bind.hpp>
#include <boost/format.hpp>

#include "global.h"


using namespace std;


const uint32_t smtp_connection_manager::RESERVE_SIZE = 200000;


smtp_connection_manager::smtp_connection_manager(uint32_t max_sess,
                                                 uint32_t max_sess_per_ip,
                                                 uint32_t n_sessions_quit_after)
    : max_sessions(max_sess)
    , max_sessions_per_ip(max_sess_per_ip)
    , n_sessions_quit_after_(n_sessions_quit_after)
    , session_count_(0)
{
    if (max_sessions_per_ip) {
      m_ip_count.reserve(max(max_sessions, RESERVE_SIZE));
    }
}


void smtp_connection_manager::start(smtp_connection_ptr conn, bool force_ssl)
{
  string msg;
  
  {
    boost::mutex::scoped_lock lock(m_mutex);

    if (max_sessions &&
        connections.size() >= max_sessions) {
      msg = "421 4.7.0 Too many connections\r\n";
    }
    else if(max_sessions_per_ip &&
            get_ip_count(conn->remote_address()) >= max_sessions_per_ip) {
      msg = str(boost::format("421 4.7.0 Too many connections from %1%\r\n")
                % conn->remote_address().to_string());
    }

    if (connections.find(conn) != connections.end()) {
      g::log().msg(r::log::alert, "ERROR: session already started");
      return;
    }
    
    connections.insert(conn);
    ip_count_inc(conn->remote_address());
  }
  
  conn->start(force_ssl, std::move(msg));
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
    
    // for debug with valgrind(callgrind) - stop after specified number of processed sessions
    if (n_sessions_quit_after_) {
      ++session_count_;
      if (session_count_ >= n_sessions_quit_after_) {
        std::exit(0);
      }
    }
}


void smtp_connection_manager::stop_all()
{
    for(auto &conn: connections) {
        conn->stop();
    }
  
    m_ip_count.clear();
}


uint32_t smtp_connection_manager::ip_count_inc(const asio::ip::address &addr)
{
  if (!max_sessions_per_ip) return 0;
  
  auto it = m_ip_count.find(addr.to_v4().to_ulong());
  if (it == m_ip_count.end()) {
    m_ip_count.insert(ip_connection_map_t::value_type(addr.to_v4().to_ulong(), 1));
    return 1;
  }
  return ++(it->second);
}


uint32_t smtp_connection_manager::ip_count_dec(const asio::ip::address &addr)
{
  if (!max_sessions_per_ip) return 0;
  
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


uint32_t smtp_connection_manager::get_ip_count(const asio::ip::address &addr) const
{
  if (!max_sessions_per_ip) return 0;
  
  auto it = m_ip_count.find(addr.to_v4().to_ulong());
  return it != m_ip_count.end() ? it->second : 0;
}
