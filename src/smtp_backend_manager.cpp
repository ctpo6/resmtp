#include "smtp_backend_manager.h"

#include <algorithm>
#include <cassert>

#include "log.h"

using namespace std;

smtp_backend_manager::smtp_backend_manager(
        const vector<server_parameters::backend_host> &h,
        uint16_t p)
    : hosts(h)
    , port(p)
{
    assert(!hosts.empty());

    weights.resize(hosts.size());
    min_weight = 1000000;
    for (uint32_t i = 0; i < hosts.size(); ++i) {
        weights[i] = hosts[i].weight;
        min_weight = std::min(min_weight,
                              static_cast<int32_t>(hosts[i].weight));
    }
    // we should start from the host with the max priority
    cur_host_idx = distance(weights.begin(),
                            max_element(weights.begin(), weights.end()));
}


smtp_backend_manager::backend_host smtp_backend_manager::get_backend_host()
{
    uint32_t idx;
    {
        lock_guard<mutex> lock(mtx);
        uint32_t bound = cur_host_idx;
        while(1) {
            if (weights[cur_host_idx] > 0) {
                weights[cur_host_idx] -= min_weight;
                idx = cur_host_idx;
                inc_cur_host_idx();
                break;
            }

            inc_cur_host_idx();

            if (cur_host_idx == bound) {
                for (uint32_t i = 0; i < weights.size(); ++i) {
                    weights[i] += hosts[i].weight;
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


void smtp_backend_manager::report_host_status(
        const backend_host &h,
        host_status s) noexcept
{
}
