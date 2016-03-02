#pragma once

#include <unistd.h>

#include <atomic>
#include <fstream>
#include <queue>
#include <string>

#include <boost/thread.hpp>
#include <boost/thread/condition.hpp>
#include <boost/thread/mutex.hpp>

#include "util.h"

using std::string;

namespace resmtp {

class LogSpamhaus {
public:

    // fname - can be nullptr or empty string: in this case file will not be
    //      created and the msg() methods will do nothing
    // exceptions:
    // std::runtime_error - if fails to open file
    void init(const char *fname, uid_t owner, gid_t group);

    void msg(string s) noexcept;

    void run();
    void stop();

    // just set the flag here, which will be processed in run()
    void recreate_log_file() { f_recreate = true; }

private:
    bool f_initialized = false;
    bool f_exit = false;
    std::atomic<bool> f_recreate;

    string file_name;
    std::ofstream ofs;

    std::queue<string> m_queue;

    boost::mutex m_condition_mutex;
    boost::condition m_condition;
};

}
