#pragma once

#include <syslog.h>

#include <cstdio>
#include <queue>
#include <string>
#include <utility>

#include <boost/thread.hpp>
#include <boost/thread/condition.hpp>
#include <boost/thread/mutex.hpp>

#include "util.h"

using std::string;

#ifdef _DEBUG
#define PDBG0(fmt, args...) fprintf(stderr, "%s:%d %s: " fmt"\n", __FILE__, __LINE__, __func__, ##args)
#define PDBG(fmt, args...) g::log().msg(resmtp::log::debug, util::strf("%s:%d %s: " fmt, __FILE__, __LINE__, __func__, ##args))
#define PLOG(prio, fmt, args...) g::log().msg(prio, util::strf("%s:%d %s: " fmt, __FILE__, __LINE__, __func__, ##args))
#else
#define PDBG(fmt, args...)
#define PDBG0(fmt, args...)
#define PLOG(prio, fmt, args...)
#endif

namespace resmtp {

enum class log : int {
    alert = LOG_ALERT,
    crit = LOG_CRIT,
    err = LOG_ERR,
    warning = LOG_WARNING,
    notice = LOG_NOTICE,
    info = LOG_INFO,
    debug = LOG_DEBUG,
    debug_extra
};

class Log {
public:
    void init(log prio_level) noexcept;

    void msg(log prio, string s) noexcept;

    void run();
    void stop();

private:
    struct Msg {
        Msg(log p, string s) : prio(p), msg(std::move(s)) {}
        log prio;
        string msg;
    };

    bool m_exit = false;
    log m_log_prio = log::crit;

    std::queue<Msg> m_queue;

    boost::mutex m_condition_mutex;
    boost::condition m_condition;
};

}
