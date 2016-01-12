#include "monitor.h"

#include <unistd.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include <mutex>
#include <vector>

#include "global.h"


using namespace std;


namespace resmtp {

struct monitor::impl_conn_t
{
    using status_t = monitor::conn_close_status_t;

    struct counters
    {
        // total number of accepted connections
        uint64_t n_conn;

        uint64_t n_conn_bl;
        uint64_t n_conn_wl;

        uint64_t n_closed_conn_ok_fast;
        uint64_t n_closed_conn_ok_tarpit;

        uint64_t n_closed_conn_fail_fast;
        uint64_t n_closed_conn_fail_tarpit;
        // counters of specific fail reasons
        uint64_t n_closed_conn_fail_client_early_write;

        uint32_t n_active_conn_max;
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
        c.n_active_conn_max = std::max(c.n_active_conn_max,
                                       c.n_active_conn_fast + c.n_active_conn_tarpit);
    }

    void on_conn_bl() noexcept
    {
        lock_guard<mutex> lock(mtx);
        ++c.n_conn_bl;
    }

    void on_conn_wl() noexcept
    {
        lock_guard<mutex> lock(mtx);
        ++c.n_conn_wl;
    }

    void conn_tarpitted() noexcept
    {
        lock_guard<mutex> lock(mtx);
        --c.n_active_conn_fast;
        ++c.n_active_conn_tarpit;
    }

    void conn_closed(status_t st, bool tarpit) noexcept
    {
        lock_guard<mutex> lock(mtx);

        if (tarpit)
            --c.n_active_conn_tarpit;
        else
            --c.n_active_conn_fast;

        if (st == status_t::ok) {
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
            if (st == status_t::fail_client_early_write)
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
        os << "conn_bl " << cc.n_conn_bl << '\n';
        os << "conn_wl " << cc.n_conn_wl << '\n';

        os << "active_conn_max " << cc.n_active_conn_max << '\n';
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


struct monitor::impl_mail_t
{
    struct counters
    {
        uint64_t n_mail_rcpt_to;
        uint64_t n_mail_delivered;
    };
    counters c;

    mutable mutex mtx;

    impl_mail_t()
    {
        memset(&c, 0, sizeof(c));
    }

    void on_mail_rcpt_to() noexcept
    {
        lock_guard<mutex> lock(mtx);
        ++c.n_mail_rcpt_to;
    }

    void on_mail_delivered() noexcept
    {
        lock_guard<mutex> lock(mtx);
        ++c.n_mail_delivered;
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

        os << "mail_rcpt_to " << cc.n_mail_rcpt_to << '\n';
        os << "mail_delivered " << cc.n_mail_delivered << '\n';
    }
};


struct monitor::impl_backend_t
{
    struct backend_ini_t
    {
        string host_name;
        uint16_t port;
        uint32_t weight;

        backend_ini_t() = default;

        backend_ini_t(string h, uint16_t p, uint32_t w) :
            host_name(h), port(p), weight(w) {}

        void print(ostream &os, uint32_t idx) const noexcept
        {
            os << "backend" << '[' << idx << "] "
               << host_name << ':' << port << ' ' << weight << '\n';
        }
    };

    struct backend_t {
        using status_t = smtp_backend_manager::host_status;

        status_t status;
        string ip_address;
        uint32_t n_active_conn;
        uint64_t n_conn;

        backend_t()
            : status(status_t::unknown)
            , ip_address("0.0.0.0")
            , n_active_conn(0)
            , n_conn(0)
        {}

        void print(ostream &os, uint32_t idx) const noexcept
        {
            os << "backend_status" << '[' << idx << "]";
            switch (status) {
            case status_t::ok:
                os << " ok "
                   << ip_address << ' '
                   << n_active_conn << ' '
                   << n_conn << '\n';
                break;
            case status_t::unknown:
                // we still haven't tried to connect to this backend
                os << " unknown "
                   << ip_address << ' '
                   << n_active_conn << ' '
                   << n_conn << '\n';
                break;
            case status_t::fail_resolve:
                os << " fail_resolve "
                   << ip_address << ' '
                   << n_active_conn << ' '
                   << n_conn << '\n';
                break;
            case status_t::fail_connect:
                os << " fail_connect "
                   << ip_address << ' '
                   << n_active_conn << ' '
                   << n_conn << '\n';
                break;
            default:
                assert(false && "unknown status code");
            }
        }
    };

    // it's immutable agter init, so no need in mutex protection
    vector<backend_ini_t> backend_ini;

    vector<backend_t> backend;
    mutable vector<mutex> mtx;


    void set_number_of_backends(uint32_t n) noexcept
    {
        backend_ini = vector<backend_ini_t>(n);
        backend = vector<backend_t>(n);
        mtx = vector<mutex>(n);
    }

    void set_backend(uint32_t idx, string h, uint16_t p, uint32_t w) noexcept
    {
        backend_ini.at(idx) = backend_ini_t(h, p, w);
    }

    void set_ip_address(uint32_t idx, string addr) noexcept
    {
        lock_guard<mutex> lock(mtx.at(idx));
        backend.at(idx).ip_address = addr;
    }

    void set_status(uint32_t idx,
                    smtp_backend_manager::host_status st) noexcept
    {
        lock_guard<mutex> lock(mtx.at(idx));
        backend.at(idx).status = st;
    }

    void on_conn(uint32_t idx) noexcept
    {
        lock_guard<mutex> lock(mtx.at(idx));
        auto &b = backend.at(idx);
        ++b.n_active_conn;
        ++b.n_conn;
    }

    void on_conn_closed(uint32_t idx) noexcept
    {
        lock_guard<mutex> lock(mtx.at(idx));
        auto &b = backend.at(idx);
        --b.n_active_conn;
    }

    void print(std::ostream &os) const noexcept
    {
        os << "backends " << backend_ini.size() << '\n';

        // print backend[]
        os << "# <host_name>:<port> <weight>\n";
        for (uint32_t i = 0; i < backend_ini.size(); ++i) {
            backend_ini[i].print(os, i + 1);
        }

        // print backend_status[]
        os << "# <status> <ip_address> <n_active_conn> <n_conn>\n";
        backend_t b;
        for (uint32_t i = 0; i < backend.size(); ++i) {
            {
                lock_guard<mutex> lock(mtx[i]);
                b = backend[i];
            }
            b.print(os, i + 1);
        }
    }
};


const char * monitor::get_conn_close_status_name(conn_close_status_t st)
{
    switch (st) {
    case conn_close_status_t::ok:
        return "ok";
    case conn_close_status_t::fail:
        return "fail";
    case conn_close_status_t::fail_client_early_write:
        return "fail_client_early_write";
        // no default: to allow gcc with -Wall produce a warning if some case: missed
    }
    assert(false && "update the switch() above");
    return nullptr;
}


monitor::monitor()
    : impl_conn(new impl_conn_t)
    , impl_mail(new impl_mail_t)
    , impl_backend(new impl_backend_t)
    , tp_start(time(NULL))
{
}


monitor::~monitor()
{
}


void monitor::print(std::ostream &os) const noexcept
{
    os << "version " << g::app_version() << '\n';
    os << "pid " << getpid() << '\n';
    os << "uptime " << time(NULL) - tp_start << '\n';
    impl_conn->print(os);
    impl_mail->print(os);
    impl_backend->print(os);
    os.flush();
}


void monitor::on_conn() noexcept
{
    impl_conn->conn();
}


void monitor::on_conn_bl() noexcept
{
    impl_conn->on_conn_bl();
}


void monitor::on_conn_wl() noexcept
{
    impl_conn->on_conn_wl();
}


void monitor::on_conn_tarpitted() noexcept
{
    impl_conn->conn_tarpitted();
}


void monitor::on_conn_closed(conn_close_status_t st, bool tarpit) noexcept
{
    impl_conn->conn_closed(st, tarpit);
}


void monitor::on_mail_rcpt_to() noexcept
{
    impl_mail->on_mail_rcpt_to();
}


void monitor::on_mail_delivered() noexcept
{
    impl_mail->on_mail_delivered();
}


void monitor::set_number_of_backends(uint32_t n) noexcept
{
    impl_backend->set_number_of_backends(n);
}


void monitor::set_backend(uint32_t idx, string h, uint16_t p, uint32_t w) noexcept
{
    impl_backend->set_backend(idx, h, p, w);
}


void monitor::on_backend_ip_address(uint32_t idx, string addr) noexcept
{
    impl_backend->set_ip_address(idx, addr);
}


void monitor::on_backend_status(uint32_t idx,
                                smtp_backend_manager::host_status st) noexcept
{
    impl_backend->set_status(idx, st);
}


void monitor::on_backend_conn(uint32_t idx) noexcept
{
    impl_backend->on_conn(idx);
}


void monitor::on_backend_conn_closed(uint32_t idx) noexcept
{
    impl_backend->on_conn_closed(idx);
}

}