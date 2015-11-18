#include <stdarg.h>
#include <stdio.h>

#include <iostream>
#include <sstream>
#include <iterator>
#include <algorithm>

#include <boost/format.hpp>

#include "uti.h"

using namespace std;

namespace util {

string strf(const char* format, ...) {
    char buf[400];
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);
    return string{ buf };
}


string str_from_buf(boost::asio::streambuf const &buf) {
    boost::asio::streambuf::const_buffers_type bufs = buf.data();
    string s(boost::asio::buffers_begin(bufs),
             boost::asio::buffers_begin(bufs) + buf.size());
    return s;
}


std::string trim(std::string s) {
    if (s.empty()) {
        return s;
    }
    std::string::size_type begin = s.find_first_not_of(" \t\n");
    if (begin == std::string::npos) {
        begin = 0;
    }
    std::string::size_type end = s.find_last_not_of(" \t\r\n") + 1;
    return s.substr(begin, end - begin);
}


std::string str_cleanup_crlf(std::string s) {
    auto rit = find_if_not(s.rbegin(), s.rend(),
                           [](char c){ return c == '\r' || c == '\n';});
    if (rit != s.rend()) {
        s.erase(rit.base(), s.end());
    }

    for(auto it = s.begin(); it != s.end();) {
        if(*it == '\r' && *(it+1) == '\n') {
            *it++ = '^';
            *it++ = 'M';
        } else {
            ++it;
        }
    }

    return s;
}


std::string rev_order_av4_str(const boost::asio::ip::address_v4& a,
                              const std::string& d) {
    return str(boost::format("%1%.%2%.%3%.%4%.%5%")
               % static_cast<int>(a.to_bytes()[3])
            % static_cast<int>(a.to_bytes()[2])
            % static_cast<int>(a.to_bytes()[1])
            % static_cast<int>(a.to_bytes()[0])
            % d);
}


std::string unfqdn(const std::string& fqdn) {
    std::size_t sz = fqdn.size();
    if (sz && fqdn[sz-1] == '.')
        return std::string(fqdn.begin(), fqdn.begin()+sz-1);
    return fqdn;
}


unsigned long djb2_hash(const unsigned char* str, size_t size)
{
    unsigned long hash = 5381;
    const unsigned char* p, *se = str + size;
    for (p=str; p!=se; ++p)
        hash = ((hash << 5) + hash) ^ *p;
    return hash;
}

} // namespace util
