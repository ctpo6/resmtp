#include "log.h"

#include <stdarg.h>

#include <utility>


using namespace std;


namespace resmtp {

log Log::m_log_prio = log::crit;

#define STRF_BUF_SIZE 1000
string Log::strf(log prio, const char* format, ...) noexcept
{
  if (!isEnabled(prio)) return string();
  
  const int sz = STRF_BUF_SIZE;
  string buf(sz, '\0');
  
  va_list ap;
  va_start(ap, format);
  int c = vsnprintf(const_cast<char *>(buf.data()), sz, format, ap);
  va_end(ap);
  
  // make size() == strlen()
  if (c < sz)
    buf.resize(c);
  else
    buf.resize(sz - 1);   // trailing '\0'

  return buf;
}


std::pair<log, string> Log::pstrf(log prio, const char *format, ...) noexcept
{
  if (!isEnabled(prio)) return make_pair(prio, string());
  
  const int sz = STRF_BUF_SIZE;
  string buf(sz, '\0');
  
  va_list ap;
  va_start(ap, format);
  int c = vsnprintf(const_cast<char *>(buf.data()), sz, format, ap);
  va_end(ap);
  
  // make size() == strlen()
  if (c < sz)
    buf.resize(c);
  else
    buf.resize(sz - 1);   // trailing '\0'

  return make_pair(prio, std::move(buf));
}


void Log::init(log log_prio) noexcept
{
    openlog("resmtp", 0, LOG_MAIL);
    m_log_prio = log_prio;
}

void Log::msg(log prio, const string &s) noexcept
{
  if (!isEnabled(prio)) return;

  boost::mutex::scoped_lock lock(m_condition_mutex);

  // make prio syslog-compatible
  if (prio == log::buffers) prio = log::debug;

  m_queue.emplace(prio, s);
  m_condition.notify_one();
}

void Log::msg(log prio, string &&s) noexcept
{
  if (!isEnabled(prio)) return;

  boost::mutex::scoped_lock lock(m_condition_mutex);

  // make prio syslog-compatible
  if (prio == log::buffers) prio = log::debug;

  m_queue.emplace(prio, std::move(s));
  m_condition.notify_one();
}

void Log::run()
{
    string msg;

    for (;;) {
        boost::mutex::scoped_lock lck(m_condition_mutex);
        while (m_queue.empty() && !m_exit) {
            m_condition.wait(lck);
        }

        if (!m_queue.empty()) {
            log prio = m_queue.front().prio;
            m_queue.front().msg.swap(msg);
            m_queue.pop();
            lck.unlock();

            const char *prefix = "";
            switch (prio) {
            case log::alert:
                prefix = "[ALERT] ";
                break;
            case log::crit:
                prefix = "[CRIT] ";
                break;
            case log::err:
                prefix = "[ERROR] ";
                break;
            case log::warning:
                prefix = "[WARNING] ";
                break;
            case log::debug:
                prefix = "[DEBUG] ";
                break;
            default:
                break;
            }

            syslog(static_cast<int>(prio), "%s%s", prefix, msg.c_str());
        } else if (m_exit) {
            break;
        }
   }
}


void Log::stop()
{
    m_exit = true;
    m_condition.notify_one();
}

}
