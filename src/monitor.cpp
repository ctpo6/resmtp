#include "monitor.h"

#include <mutex>

#include "global.h"


using namespace std;


namespace resmtp {

struct monitor::impl_conn_t
{
    void conn() noexcept
    {
        lock_guard<mutex> lock(mtx);
        ++n_conn;
        ++n_active_conn;
        ++n_active_conn_fast;
    }

    void conn_tarpitted() noexcept
    {
        lock_guard<mutex> lock(mtx);
        --n_active_conn_fast;
        ++n_active_conn_tarpit;
    }

    void conn_closed(bool tarpitted) noexcept
    {
        lock_guard<mutex> lock(mtx);
        --n_active_conn;
        if (tarpitted)
            --n_active_conn_tarpit;
        else
            --n_active_conn_fast;
    }

    void print(std::ostream &os) const noexcept
    {
        lock_guard<mutex> lock(mtx);
        os << "conn " << n_conn << '\n';
        os << "active_conn " << n_active_conn << '\n';
        os << "active_conn_fast " << n_active_conn_fast << '\n';
        os << "active_conn_tarpit " << n_active_conn_tarpit << '\n';
    }

    uint64_t n_conn = 0;
    uint32_t n_active_conn = 0;
    uint32_t n_active_conn_fast = 0;
    uint32_t n_active_conn_tarpit = 0;

    mutable mutex mtx;
};



monitor::monitor()
    : impl_conn(new impl_conn_t)
{
}


monitor::~monitor()
{
}


void monitor::print(std::ostream &os) const noexcept
{
    os << "version " << g::app_version() << '\n';
    impl_conn->print(os);
}


void monitor::conn() noexcept
{
    impl_conn->conn();
}


void monitor::conn_tarpitted() noexcept
{
    impl_conn->conn_tarpitted();
}


void monitor::conn_closed(bool tarpitted) noexcept
{
    impl_conn->conn_closed(tarpitted);
}


}