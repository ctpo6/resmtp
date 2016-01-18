#include "pidfile.h"

#include <unistd.h>

#include <fstream>
#include <utility>


using namespace std;


bool PidFile::create(string fname) noexcept
{
    if (fname.empty()) {
        return false;
    }

    m_pid_file_name = std::move(fname);
    std::ofstream s(m_pid_file_name);
    s << getpid() << std::endl;

    return s.good();
}


bool PidFile::unlink() noexcept
{
    if (!m_pid_file_name.empty()) {
        return ::unlink(m_pid_file_name.c_str());
    }
    return false;
}
