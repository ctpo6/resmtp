#include "smtp_backend_manager.h"

#include <algorithm>
#include <cassert>
#include <cstdlib>

#include <boost/format.hpp>

#include "global.h"
#include "log.h"
#include "options.h"

using namespace std;
using namespace std::chrono;

smtp_backend_manager::smtp_backend_manager(
        const vector<server_parameters::backend_host> &h,
        uint16_t p)
    : hosts(h)
    , port(p)
{
    assert(!hosts.empty());

    // init weight[], find min_weight
    weight.resize(hosts.size());
    int32_t max_weight = max_element(
        hosts.begin(),
        hosts.end(),
        [](const server_parameters::backend_host &a,
            const server_parameters::backend_host &b) { return a.weight < b.weight; })->weight;
    min_weight = max_weight;
    for (uint32_t i = 0; i < hosts.size(); ++i) {
        weight[i] = hosts[i].weight - max_weight / 2;
        min_weight = std::min(min_weight,
                              static_cast<int32_t>(hosts[i].weight));
    }

    // we should start from the host with the max priority
    cur_host_idx = distance(weight.begin(),
                            max_element(weight.begin(), weight.end()));

    status.resize(hosts.size(), host_status::unknown);
    fail_expiration_tp.resize(hosts.size(), 0);

    // initialize backend hosts in monitor
    g::mon().set_number_of_backends(hosts.size());
    for (uint32_t i = 0; i < hosts.size(); ++i) {
        g::mon().set_backend(i, hosts[i].host_name, port, hosts[i].weight);
    }
}


smtp_backend_manager::backend_host smtp_backend_manager::get_backend_host()
{
    uint32_t idx;
    {
        lock_guard<mutex> lock(mtx);
        uint32_t bound = cur_host_idx;
        while(1) {
            if (weight[cur_host_idx] > 0) {
                if (status[cur_host_idx] != host_status::ok) {
                    if (status[cur_host_idx] == host_status::unknown
                            || system_clock::to_time_t(system_clock::now()) >= fail_expiration_tp[cur_host_idx]) {
                        status[cur_host_idx] = host_status::ok;
                        g::mon().on_backend_status(cur_host_idx, host_status::ok);
                    }
                }

                if (status[cur_host_idx] == host_status::ok) {
                    weight[cur_host_idx] -= min_weight;
                    idx = cur_host_idx;
                    inc_cur_host_idx();
                    break;
                }
            }

            inc_cur_host_idx();

            if (cur_host_idx == bound) {
                bool all_offline = true;
                for (uint32_t i = 0; i < weight.size(); ++i) {
                    if (weight[i] <= 0) {
                        weight[i] += hosts[i].weight;
                    }
                    if (status[i] == host_status::ok) {
                        all_offline = false;
                    }
                }

                if (all_offline) {
                    throw std::runtime_error("all backend hosts are offline");
                }
            }
        }
        // unlock mtx
    }

    g_log.msg(MSG_DEBUG,
              str(boost::format("selected backend host: %1% %2%")
                  % hosts[idx].host_name
                  % hosts[idx].weight));

    return backend_host(idx, hosts[idx].host_name, port);
}


void smtp_backend_manager::on_host_fail(
        const backend_host &h,
        host_status st) noexcept
{
    PDBG("idx=%u name=%s st=%d", h.index, h.host_name.c_str(), (int)st);

    lock_guard<mutex> lock(mtx);

    status[h.index] = st;
    fail_expiration_tp[h.index] = system_clock::to_time_t(system_clock::now());

    switch (st) {
    case host_status::fail_resolve:
        fail_expiration_tp[h.index] +=
                static_cast<time_t>(10 * g::cfg().backend_connect_timeout);
        break;
    case host_status::fail_connect:
        fail_expiration_tp[h.index] +=
                static_cast<time_t>((1 + std::rand() % 10) * g::cfg().backend_connect_timeout);
        break;
#if 0
        // this status code is not used now
    case host_status::fail:
        fail_expiration_tp[h.index] +=
                static_cast<time_t>((1 + std::rand() % 10) * g::cfg().backend_connect_timeout);
        break;
#endif
    default:
        assert(false && "this function must be called with a fail status only");
    }

    g::mon().on_backend_status(h.index, st);
}
