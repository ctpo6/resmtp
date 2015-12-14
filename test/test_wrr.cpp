#include <algorithm>
#include <iostream>
#include <vector>

using namespace std;

class smtp_backend_manager {
public:

    smtp_backend_manager(vector<uint32_t> w)
        : ini_weight(w)
    {
        weight.resize(ini_weight.size());
        min_weight = 1000000;
        int32_t max_w = *max_element(ini_weight.begin(), ini_weight.end());
        for (uint32_t i = 0; i < ini_weight.size(); ++i) {
            weight[i] = ini_weight[i] - max_w / 2;
            min_weight = std::min(min_weight,
                                  static_cast<int32_t>(ini_weight[i]));
        }
        cur_host_idx = distance(weight.begin(),
                                max_element(weight.begin(), weight.end()));
    }

    uint32_t get_backend_host()
    {
        uint32_t idx;
        uint32_t bound = cur_host_idx;
        while (1) {
            if (weight[cur_host_idx] > 0) {
                weight[cur_host_idx] -= min_weight;
                idx = cur_host_idx;
                inc_cur_host_idx();
                break;
            }

            inc_cur_host_idx();

            if (cur_host_idx == bound) {
                for (uint32_t i = 0; i < weight.size(); ++i) {
                    if (weight[i] <= 0) {
                        weight[i] += ini_weight[i];
                    }
                }
//                inc_cur_host_idx();
            }
        }

        return idx;
    }

private:

    inline void inc_cur_host_idx() noexcept
    {
        if (++cur_host_idx == ini_weight.size()) {
            cur_host_idx = 0;
        }
    }

    const vector<uint32_t> ini_weight;

    uint32_t cur_host_idx;

    int32_t min_weight;
    vector<int32_t> weight;
};


int main()
{
    smtp_backend_manager m({100, 100, 100});
    for (uint32_t i = 0; i < 30; ++i) {
        cout << m.get_backend_host() << ' ';
    }
    cout << endl;
}
