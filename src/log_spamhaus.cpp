#include "log_spamhaus.h"

#include <exception>
#include <utility>


using namespace std;


namespace resmtp {

void LogSpamhaus::init(const char *fname)
{
    if (!fname || !fname[0]) return;

    ofs.open(fname, ios_base::out | ios_base::app);
    if (!ofs) {
        throw std::runtime_error("can't open spamhaus log file");
    }
    initialized = true;
}


void LogSpamhaus::msg(string s) noexcept
{
    if (!initialized) return;

    boost::mutex::scoped_lock lock(m_condition_mutex);
    m_queue.push(std::move(s));
    m_condition.notify_one();
}


void LogSpamhaus::run()
{
    string buffer;
    for (;;) {
        boost::mutex::scoped_lock lock(m_condition_mutex);
        while (m_queue.empty() && !m_exit) {
            m_condition.wait(lock);
        }

        if (!m_queue.empty()) {
            m_queue.front().swap(buffer);
            m_queue.pop();

            lock.unlock();
            ofs << buffer << endl;
        } else if (m_exit) {
            break;
        }
   }
}


void LogSpamhaus::stop()
{
    m_exit = true;
    m_condition.notify_one();
}

}
