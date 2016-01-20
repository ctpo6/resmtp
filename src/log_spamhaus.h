#pragma once

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
    void init(const char *fname);

    void msg(string s) noexcept;

    void run();
    void stop();

private:
    bool initialized = false;
    bool m_exit = false;

    std::ofstream ofs;

    std::queue<string> m_queue;

    boost::mutex m_condition_mutex;
    boost::condition m_condition;
};

}
