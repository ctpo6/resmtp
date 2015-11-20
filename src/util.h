#ifndef _UTI_H_
#define _UTI_H_

#include <cstring>
#include <string>

#include <boost/asio.hpp>

namespace util {

std::string strf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
std::string str_from_buf(boost::asio::streambuf const &buf);

/*
 * Trim whitespaces at the beginning and the at the end.
 */
std::string trim(std::string s);

/*
 * Replace CRLF inside the string with "^M"; trim trailing CRLF.
 * Used for logging.
 */
std::string str_cleanup_crlf(std::string s);

std::string rev_order_av4_str(const boost::asio::ip::address_v4&, const std::string& domain);

std::string unfqdn(const std::string& fqdn); // remove last dot from fqdn, if any

unsigned long djb2_hash(const unsigned char* str, size_t size);

inline bool parse_email(const std::string& email,
                        std::string& name,
                        std::string& domain) {
    if (const char* at = strchr(email.c_str(), '@')) {
        name = std::string(email.c_str(), at);
        domain = std::string(at+1, email.c_str() + email.size());
        return true;
    }
    return false;
}

} // namespace util

#endif
