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


#ifdef _DEBUG
#define PDBG0(fmt, args...) fprintf(stderr, "%s:%d %s: " fmt"\n", __FILE__, __LINE__, __func__, ##args)
#else
#define PDBG0(fmt, args...)
#endif

#define PDBG(fmt, args...) g::log().msg(resmtp::log::debug, resmtp::Log::strf(resmtp::log::debug, "%s:%d %s: " fmt, __FILE__, __LINE__, __func__, ##args))
#define PLOG(prio, fmt, args...) g::log().msg(prio, resmtp::Log::strf(prio, "%s:%d %s: " fmt, __FILE__, __LINE__, __func__, ##args))


using std::string;

namespace resmtp {

enum class log : int {
    alert = LOG_ALERT,
    crit = LOG_CRIT,
    err = LOG_ERR,
    warning = LOG_WARNING,
    notice = LOG_NOTICE,
    info = LOG_INFO,
    debug = LOG_DEBUG,
    buffers
};

class Log {
public:
    void init(log prio_level) noexcept;

    void msg(log prio, const string &s) noexcept;
    void msg(log prio, string &&s) noexcept;
    void msg(const std::pair<log, string> &m) noexcept
    {
      msg(m.first, std::move(m.second));
    }

    void run();
    void stop();
    
    // true - message with log_level is enabled, false - disabled
    static bool isEnabled(log log_level) noexcept
    {
      return log_level <= m_log_prio;
    }

    static string strf(log prio, const char *fmt, ...) noexcept __attribute__((format(printf, 2, 3)));
    static std::pair<log, string> pstrf(log prio, const char *fmt, ...) noexcept __attribute__((format(printf, 2, 3)));
    
private:
    struct Msg {
        Msg(log p, string s) : prio(p), msg(std::move(s)) {}
        log prio;
        string msg;
    };

    bool m_exit = false;
    
    static log m_log_prio;

    std::queue<Msg> m_queue;

    boost::mutex m_condition_mutex;
    boost::condition m_condition;
};

}
