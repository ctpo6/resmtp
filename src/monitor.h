#pragma once

#include <cstdint>
#include <ctime>
#include <memory>
#include <ostream>
#include <string>

#include <boost/noncopyable.hpp>

using std::string;

namespace resmtp {

class monitor : private boost::noncopyable
{
public:
    enum class status
    {
        ok = 0,
        fail,
        // connection was closed by resmtp because client sarted writing to the
        // socket before receiving a greeting message
        fail_client_early_write
    };

    monitor();
    ~monitor();

    void print(std::ostream &os) const noexcept;

    void conn() noexcept;
    void conn_tarpitted() noexcept;
    void conn_closed(status st, bool tarpit) noexcept;

    void set_number_of_backends(uint32_t n);
    void set_backend(uint32_t idx,
                     string host_name,
                     uint16_t port,
                     uint32_t weight);

    // initialize vector of backend hosts
    void backend_push_back(string host_name,
                           uint16_t port,
                           uint32_t weight);
    // set current IP address of backend
    void set_backend_ip_address(uint32_t idx, string addr);

private:
    struct impl_conn_t;
    std::unique_ptr<impl_conn_t> impl_conn;

    struct impl_backend_t;
    std::unique_ptr<impl_backend_t> impl_backend;

    std::time_t tp_start;
};
}
