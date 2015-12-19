#include "monitor.h"

#include <cstring>
#include <mutex>

#include "global.h"


using namespace std;


namespace resmtp {

struct monitor::impl_conn_t
{
    using status = monitor::status;

    struct counters
    {
        // total number of accepted connections
        uint64_t n_conn;

        uint64_t n_closed_conn_ok_fast;
        uint64_t n_closed_conn_ok_tarpit;

        uint64_t n_closed_conn_fail_fast;
        uint64_t n_closed_conn_fail_tarpit;

        uint32_t n_active_conn_fast;
        uint32_t n_active_conn_tarpit;
    };
    counters c;

    mutable mutex mtx;

    impl_conn_t()
    {
        memset(&c, 0, sizeof(c));
    }

    void conn() noexcept
    {
        lock_guard<mutex> lock(mtx);
        ++c.n_conn;
        ++c.n_active_conn_fast;
    }

    void conn_tarpitted() noexcept
    {
        lock_guard<mutex> lock(mtx);
        --c.n_active_conn_fast;
        ++c.n_active_conn_tarpit;
    }

    void conn_closed(status st, bool tarpit) noexcept
    {
        lock_guard<mutex> lock(mtx);

        if (tarpit)
            --c.n_active_conn_tarpit;
        else
            --c.n_active_conn_fast;

        if (st == status::ok) {
            if (tarpit)
                ++c.n_closed_conn_ok_tarpit;
            else
                ++c.n_closed_conn_ok_fast;
        } else {
            if (tarpit)
                ++c.n_closed_conn_fail_tarpit;
            else
                ++c.n_closed_conn_fail_fast;
        }
    }

    void print(std::ostream &os) const noexcept
    {
        // first get a local copy to release the mutex as fast as possible
        counters cc;
        {
            lock_guard<mutex> lock(mtx);
            cc = c;
        }

        // now can slowly print to the stream
        os << "conn " << cc.n_conn << '\n';

        os << "active_conn " << cc.n_active_conn_fast + cc.n_active_conn_tarpit << '\n';
        os << "active_conn_fast " << cc.n_active_conn_fast << '\n';
        os << "active_conn_tarpit " << cc.n_active_conn_tarpit << '\n';

        uint64_t closed_conn_ok = cc.n_closed_conn_ok_fast
                + cc.n_closed_conn_ok_tarpit;
        uint64_t closed_conn_fail = cc.n_closed_conn_fail_fast
                + cc.n_closed_conn_fail_tarpit;
        uint64_t closed_conn = closed_conn_ok + closed_conn_fail;

        os << "closed_conn " << closed_conn << '\n';

        os << "closed_conn_ok " << closed_conn_ok << '\n';
        os << "closed_conn_ok_fast " << cc.n_closed_conn_ok_fast << '\n';
        os << "closed_conn_ok_tarpit " << cc.n_closed_conn_ok_tarpit << '\n';

        os << "closed_conn_fail " << closed_conn_fail << '\n';
        os << "closed_conn_fail_fast " << cc.n_closed_conn_fail_fast << '\n';
        os << "closed_conn_fail_tarpit " << cc.n_closed_conn_fail_tarpit << '\n';
    }
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


void monitor::conn_closed(status st, bool tarpit) noexcept
{
    impl_conn->conn_closed(st, tarpit);
}


}