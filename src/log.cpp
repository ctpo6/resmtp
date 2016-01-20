#include "log.h"

#include <syslog.h>

using namespace std;


namespace resmtp {

void Log::init(uint32_t log_prio) noexcept
{
    openlog("resmtp", 0, LOG_MAIL);
    m_log_prio = log_prio;
}


void Log::msg(uint32_t prio, string s) noexcept
{
    if (prio <= m_log_prio) {
        boost::mutex::scoped_lock lck(m_condition_mutex);
        if (prio == MSG_CRITICAL || prio == MSG_VERY_CRITICAL) {
            // TODO to avoid string realloc, place prio to the queue and print it in run()
            m_queue.push(string("[CRITICAL] ") + s);
        } else if (prio >= MSG_DEBUG) {
            m_queue.push(string("[DEBUG] ") + s);
        } else {
            m_queue.push(s);
        }
        m_condition.notify_one();
    }
}


void Log::run()
{
    string buffer;
    for (;;) {
        boost::mutex::scoped_lock lck(m_condition_mutex);
        while (m_queue.empty() && !m_exit) {
            m_condition.wait(lck);
        }

        if (!m_queue.empty()) {
            m_queue.front().swap(buffer);
            m_queue.pop();

            lck.unlock();
            syslog(LOG_INFO, "%s", buffer.c_str());
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
