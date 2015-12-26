#ifndef _LOG_H_
#define _LOG_H_

#include <syslog.h>

#include <cstdio>
#include <queue>
#include <string>

#include <boost/thread.hpp>
#include <boost/thread/condition.hpp>
#include <boost/thread/mutex.hpp>

#include "util.h"

const uint32_t MSG_VERY_CRITICAL = 1;
const uint32_t MSG_CRITICAL = 10;
const uint32_t MSG_NORMAL = 20;
const uint32_t MSG_DEBUG = 50;
const uint32_t MSG_DEBUG_BUFFERS = 100;

#ifdef _DEBUG
#define PDBG(fmt, args...) g_log.msg(MSG_DEBUG, util::strf("%s:%d %s: " fmt, __FILE__, __LINE__, __func__, ##args))
#define PDBG0(fmt, args...) fprintf(stderr, "%s:%d %s: " fmt"\n", __FILE__, __LINE__, __func__, ##args)
#else
#define PDBG(fmt, args...)
#define PDBG0(fmt, args...)
#endif

class logger {
public:
    void init(const char *ident, int log_prio);

    void msg(uint32_t prio, std::string s) noexcept;

    void msg(uint32_t prio, const char *s) noexcept
    {
        msg(prio, std::string(s));
    }

    void run();
    void stop();

protected:
    bool m_exit = false;
    uint32_t m_log_prio = MSG_CRITICAL;

    std::queue<std::string> m_queue;

    boost::mutex m_condition_mutex;
    boost::condition m_condition;
};

extern logger g_log;

#endif // _LOG_H_
