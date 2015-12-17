#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "rfc_date.h"

using namespace std;

#define DAY_MIN         1440

#define STRFTIME_FMT "%a, %e %b %Y %H:%M:%S "

std::string mail_date(time_t when)
{
    struct tm gmt;
    gmtime_r(&when, &gmt);
    struct tm lt;
    localtime_r(&when, &lt);

    int gmtoff = (lt.tm_hour - gmt.tm_hour) * 60 + lt.tm_min - gmt.tm_min;

    if (lt.tm_year < gmt.tm_year)
        gmtoff -= DAY_MIN;
    else if (lt.tm_year > gmt.tm_year)
        gmtoff += DAY_MIN;
    else if (lt.tm_yday < gmt.tm_yday)
        gmtoff -= DAY_MIN;
    else if (lt.tm_yday > gmt.tm_yday)
        gmtoff += DAY_MIN;

    if (lt.tm_sec <= gmt.tm_sec - 60)
        gmtoff -= 1;
    else if (lt.tm_sec >= gmt.tm_sec + 60)
        gmtoff += 1;

    if (gmtoff < -DAY_MIN || gmtoff > DAY_MIN) {
        // error
    }

    char buffer[200];
    size_t c = strftime(buffer, sizeof(buffer), STRFTIME_FMT, &lt);
    snprintf(buffer + c, sizeof(buffer) - c, "%+03d%02d",
             gmtoff / 60,
             abs(gmtoff) % 60);

//    strftime(buffer, sizeof(buffer), " (%Z)", lt);

    return string(buffer);
}
