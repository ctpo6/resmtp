#include <iostream>
#include "log.h"

logger g_log;


void logger::init(const char *ident, int log_prio) {
    openlog(ident, 0, LOG_MAIL);
    m_log_prio = log_prio;
}


void logger::msg(uint32_t prio, const std::string &msg_) noexcept {
    if (prio <= m_log_prio) {
        boost::mutex::scoped_lock lck(m_condition_mutex);
        m_queue.push(msg_);
        m_condition.notify_one();
    }
}


void logger::run() {
    std::string buffer;
    for (;;) {
        boost::mutex::scoped_lock lck(m_condition_mutex);
        while (m_queue.empty() && !m_exit)
            m_condition.wait(lck);

        if (!m_queue.empty()) {
            m_queue.front().swap(buffer);
            m_queue.pop();

            lck.unlock();
            syslog(LOG_INFO, "%s", buffer.c_str());
        }
        else if (m_exit)
            break;
   }
}


void logger::stop()
{
    m_exit = true;
    m_condition.notify_one();
}
