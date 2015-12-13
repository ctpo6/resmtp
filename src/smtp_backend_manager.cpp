#include "smtp_backend_manager.h"

#include <algorithm>
#include <cassert>

#include "log.h"

using namespace std;
using namespace std::chrono;

smtp_backend_manager::smtp_backend_manager(
        const vector<server_parameters::backend_host> &h,
        uint16_t p)
    : hosts(h)
    , port(p)
{
    assert(!hosts.empty());

    weight.resize(hosts.size());
    min_weight = 1000000;
    for (uint32_t i = 0; i < hosts.size(); ++i) {
        weight[i] = hosts[i].weight;
        min_weight = std::min(min_weight,
                              static_cast<int32_t>(hosts[i].weight));
    }
    // we should start from the host with the max priority
    cur_host_idx = distance(weight.begin(),
                            max_element(weight.begin(), weight.end()));

    status.resize(hosts.size(), host_status::ok);
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
                    time_t dt = system_clock::to_time_t(system_clock::now()) -
                            status_tp[cur_host_idx];
                    bool expired;
                    switch (status[cur_host_idx]) {
                    case host_status::fail_connect:
                        // too many connections to backend?
                        expired = (dt > static_cast<time_t>(30));
                        break;
                    case host_status::fail:
                    case host_status::fail_resolve:
                        // backend has gone offline?
                        expired = (dt > static_cast<time_t>(5*60));
                        break;
                    default:
                        assert(false && "unreachable");
                    }

                    if (expired) {
                        status[cur_host_idx] = host_status::ok;
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

                inc_cur_host_idx();
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


void smtp_backend_manager::report_host_fail(
        const backend_host &h,
        host_status st) noexcept
{
    assert(st != host_status::ok && "only fail must be reported");

    lock_guard<mutex> lock(mtx);
    status[h.index] = st;
    status_tp[h.index] = system_clock::to_time_t(system_clock::now());
}
