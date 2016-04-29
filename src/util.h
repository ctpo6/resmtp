#ifndef _UTIL_H_
#define _UTIL_H_

#include <cstring>
#include <string>

#include <boost/asio.hpp>

using std::string;

namespace util {

string strf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
string str_from_buf(boost::asio::streambuf const &buf);

/*
 * Trim whitespaces at the beginning and the at the end.
 */
string trim(std::string s);

/*
 * Replace CRLF inside the string with "^M"; trim trailing CRLF.
 * Used for logging.
 */
string str_cleanup_crlf(string s);

string rev_order_av4_str(const boost::asio::ip::address_v4&,
                         const string &domain);

string unfqdn(const string &fqdn); // remove last dot from fqdn, if any

unsigned long djb2_hash(const unsigned char* str, size_t size);

inline bool parse_email(const string &email,
                        string &name,
                        string &domain) {
    if (const char* at = strchr(email.c_str(), '@')) {
        name = string(email.c_str(), at);
        domain = string(at+1, email.c_str() + email.size());
        return true;
    }
    return false;
}

} // namespace util

#endif
