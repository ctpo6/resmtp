#pragma once

#include <cstdint>
#include <memory>
#include <ostream>

#include <boost/noncopyable.hpp>


namespace resmtp {

class monitor : private boost::noncopyable
{
public:
    monitor();
    ~monitor();

    void print(std::ostream &os) const noexcept;

    void conn() noexcept;
    void conn_tarpitted() noexcept;
    void conn_closed(bool tarpitted) noexcept;

private:
    struct impl_conn_t;
    std::unique_ptr<impl_conn_t> impl_conn;

};
}
