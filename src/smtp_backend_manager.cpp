#include "smtp_backend_manager.h"

#include <exception>

using namespace std;

smtp_backend_manager::smtp_backend_manager(
        const vector<string> &h,
        uint16_t p)
    : hosts(h)
    , port(p)
{
    if (hosts.empty()) {
        throw std::runtime_error("no backend hosts specified");
    }
}


void smtp_backend_manager::get_backend_host(remote_point &h)
{
    h.index = 0;
    h.host_name = hosts[0];
    h.port = port;
}


void smtp_backend_manager::report_host_status(
        const remote_point &r,
        host_status s) noexcept
{
}
