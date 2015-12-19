#pragma once

#include <cstdint>
#include <ctime>
#include <memory>
#include <ostream>

#include <boost/noncopyable.hpp>


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

private:
    struct impl_conn_t;
    std::unique_ptr<impl_conn_t> impl_conn;

    std::time_t tp_start;
};
}
