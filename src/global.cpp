#include "global.h"

namespace g {

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
