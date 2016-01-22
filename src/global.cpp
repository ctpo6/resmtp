#include "global.h"

#include <csignal>

namespace g {

volatile static std::sig_atomic_t stop_flag = 0;

void set_stop_flag() noexcept
{
    stop_flag = 1;
}

bool get_stop_flag() noexcept
{
    return stop_flag;
}


server_parameters & cfg() noexcept
{
    static server_parameters c;
    return c;
}


resmtp::Log & log() noexcept
{
    static resmtp::Log l;
    return l;
}


resmtp::LogSpamhaus & logsph() noexcept
{
    static resmtp::LogSpamhaus l;
    return l;
}


resmtp::monitor & mon() noexcept
{
    static resmtp::monitor m;
    return m;
}


PidFile & pid_file() noexcept
{
    static PidFile pf;
    return pf;
}

}
