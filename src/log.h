#pragma once

#include <cstdio>
#include <queue>
#include <string>

#include <boost/thread.hpp>
#include <boost/thread/condition.hpp>
#include <boost/thread/mutex.hpp>

#include "util.h"

using std::string;

const uint32_t MSG_VERY_CRITICAL = 1;
const uint32_t MSG_CRITICAL = 10;
const uint32_t MSG_NORMAL = 20;
const uint32_t MSG_DEBUG = 50;
const uint32_t MSG_DEBUG_BUFFERS = 100;

#ifdef _DEBUG
#define PDBG(fmt, args...) g::log().msg(MSG_DEBUG, util::strf("%s:%d %s: " fmt, __FILE__, __LINE__, __func__, ##args))
#define PDBG0(fmt, args...) fprintf(stderr, "%s:%d %s: " fmt"\n", __FILE__, __LINE__, __func__, ##args)
#define PLOG(prio, fmt, args...) g::log().msg(prio, util::strf("%s:%d %s: " fmt, __FILE__, __LINE__, __func__, ##args))
#else
#define PDBG(fmt, args...)
#define PDBG0(fmt, args...)
#define PLOG(prio, fmt, args...)
#endif

namespace resmtp {

class Log {
public:
    void init(uint32_t log_prio) noexcept;

    void msg(uint32_t prio, string s) noexcept;

    void run();
    void stop();

private:
    bool m_exit = false;
    uint32_t m_log_prio = MSG_CRITICAL;

    std::queue<string> m_queue;

    boost::mutex m_condition_mutex;
    boost::condition m_condition;
};

}
