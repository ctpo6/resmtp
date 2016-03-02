#include "log_spamhaus.h"

#include <exception>
#include <utility>

#include "global.h"


using namespace std;


namespace resmtp {

void LogSpamhaus::init(const char *fname, uid_t owner, gid_t group)
{
    if (!fname || !fname[0]) return;

    ofs.open(fname, ios_base::out | ios_base::app);
    if (!ofs) {
        throw std::runtime_error("can't open spamhaus log file");
    }

    // chown the file to have an ability to recreate it later (on SIGHUP)
    if (chown(fname, owner, group) != 0) {
        throw std::runtime_error("can't chown spamhaus log file");
    }

    file_name = fname;
    f_recreate = false;
    f_initialized = true;
}


void LogSpamhaus::msg(string s) noexcept
{
    if (!f_initialized) return;

    boost::mutex::scoped_lock lock(m_condition_mutex);
    m_queue.push(std::move(s));
    m_condition.notify_one();
}


void LogSpamhaus::run()
{
    string buffer;
    for (;;) {
        boost::mutex::scoped_lock lock(m_condition_mutex);
        while (m_queue.empty() && !f_exit) {
            m_condition.wait(lock);
        }

        if (!m_queue.empty()) {
            m_queue.front().swap(buffer);
            m_queue.pop();

            lock.unlock();

            if (f_recreate) {
                ofs.close();
                ofs.open(file_name);    // truncate file if already exists
                f_recreate = false;
            }

            ofs << buffer << endl;

            // monitor ofs state: investigate what happens when fs is full
            g::mon().set_spamhaus_log_file_iostate(ofs.rdstate());
        } else if (f_exit) {
            break;
        }
   }
}


void LogSpamhaus::stop()
{
    f_exit = true;
    m_condition.notify_one();
}

}
