#ifndef _TIMER_H_
#define _TIMER_H_

#include <ctime>
#include <string>

using std::string;

class timer
{
public:
    timer();

    void start();

    time_t mark(bool _diff=true);
    time_t restart(bool _diff=true);

    static string format_time(time_t _time);

protected:
    time_t m_time;
};

#endif
