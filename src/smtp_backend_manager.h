#ifndef _SMTP_BACKEND_MANAGER_H_
#define _SMTP_BACKEND_MANAGER_H_

#include <ctime>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <utility>

#include <boost/noncopyable.hpp>

#include "options.h"

using std::string;
using std::vector;

class smtp_backend_manager : private boost::noncopyable
{
public:
    struct backend_host
    {
        backend_host() = default;
        backend_host(uint32_t i, string h, uint16_t p) :
            index(i), host_name(std::move(h)), port(p) {}
        uint32_t index;     // internal index
        string host_name;   // IP or symbolic
        uint16_t port;      // TCP port
    };

    enum class host_status
    {
        unknown = 0,
        ok,
//        fail,
        fail_resolve,
        fail_connect
    };

    smtp_backend_manager(const vector<server_parameters::backend_host> &h,
                         uint16_t p);

    // throws if failed
    backend_host get_backend_host();

    // called by smtp_client to report host operation result
    void on_host_fail(const backend_host &h, host_status st) noexcept;

private:

    inline void inc_cur_host_idx() noexcept
    {
        if (++cur_host_idx == hosts.size()) {
            cur_host_idx = 0;
        }
    }

    const vector<server_parameters::backend_host> hosts;
    const uint16_t port;

    uint32_t cur_host_idx;

    int32_t min_weight;
    vector<int32_t> weight;

    vector<host_status> status;
    // time point of the fail status expiration
    vector<std::time_t> fail_expiration_tp;

    std::mutex mtx;
};

#endif