#pragma once

#include <string>

using std::string;

struct PidFile
{
    bool create(string fname) noexcept;
    bool unlink() noexcept;

    string m_pid_file_name;
};
