#include "log.h"


using namespace std;


namespace resmtp {

void Log::init(log log_prio) noexcept
{
    openlog("resmtp", 0, LOG_MAIL);
    m_log_prio = log_prio;
}


void Log::msg(log prio, string s) noexcept
{
    if (prio > m_log_prio) return;

    boost::mutex::scoped_lock lck(m_condition_mutex);

    // make prio syslog-compatible
    if (prio == log::debug_extra) prio = log::debug;

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

            syslog(LOG_INFO, "%s%s", prefix, msg.c_str());
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
