#pragma once

#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>

#include "net/dns_resolver.hpp"

namespace ba = boost::asio;
namespace bs = boost::system;

using std::string;
using std::vector;

class smtp_backend_manager :
        public boost::enable_shared_from_this<smtp_backend_manager>,
        private boost::noncopyable {
public:

    struct remote_point {
        uint32_t index;     // internal index
        string host_name;   // IP or symbolic
        uint16_t port;      // TCP port
    };

    enum class host_status {
        ok = 0,
        fail,
        fail_resolve,
        fail_connect
    };

    smtp_backend_manager(const vector<string> &hosts,
                         uint16_t port);

    // throws if failed
    void get_backend_host(remote_point &h);

    // called by smtp_client to report host operation result
    void report_host_status(const remote_point &r, host_status s) noexcept;

private:

    vector<string> hosts;
    uint16_t port;
};
