#include "monitor.h"

#include <unistd.h>

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
        // counters of specific fail reasons
        uint64_t n_closed_conn_fail_client_early_write;

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
            // all fail statuses come here
            if (tarpit)
                ++c.n_closed_conn_fail_tarpit;
            else
                ++c.n_closed_conn_fail_fast;
            // update specific fail reason counters
            if (st == status::fail_client_early_write)
                ++c.n_closed_conn_fail_client_early_write;
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
        os << "closed_conn_fail_client_early_write " << cc.n_closed_conn_fail_client_early_write << '\n';
    }
};


monitor::monitor()
    : impl_conn(new impl_conn_t)
    , tp_start(time(NULL))
{
}


monitor::~monitor()
{
}


void monitor::print(std::ostream &os) const noexcept
{
    os << "pid " << getpid() << '\n';
    os << "uptime " << time(NULL) - tp_start << '\n';
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