#pragma once

#include <cstdint>
#include <ctime>
#include <memory>
#include <ostream>
#include <string>

#include <boost/noncopyable.hpp>

#include "smtp_backend_manager.h"

using std::string;

namespace resmtp {

class monitor : private boost::noncopyable
{
public:
    enum class conn_close_status_t
    {
        ok = 0,
        fail,
        // connection was closed by resmtp because client sarted writing to the
        // socket before receiving a greeting message
        fail_client_early_write
    };
    static const char * get_conn_close_status_name(conn_close_status_t st);


    monitor();
    ~monitor();

    void print(std::ostream &os) const noexcept;

    void conn() noexcept;
    void conn_tarpitted() noexcept;
    void conn_closed(conn_close_status_t st, bool tarpit) noexcept;

    // backend initialization
    void set_number_of_backends(uint32_t n) noexcept;
    void set_backend(uint32_t idx,
                     string host_name,
                     uint16_t port,
                     uint32_t weight) noexcept;

    // report current IP address of backend
    void on_backend_ip_address(uint32_t idx, string addr) noexcept;

    // report current status of backend
    void on_backend_status(uint32_t idx,
                           smtp_backend_manager::host_status st) noexcept;

    // report connection to backend established
    void on_backend_conn(uint32_t idx) noexcept;
    // report connection to backend closed
    void on_backend_conn_closed(uint32_t idx) noexcept;

private:
    struct impl_conn_t;
    std::unique_ptr<impl_conn_t> impl_conn;

    struct impl_backend_t;
    std::unique_ptr<impl_backend_t> impl_backend;

    std::time_t tp_start;
};
}
