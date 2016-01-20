#pragma once

#include "log.h"
#include "log_spamhaus.h"
#include "monitor.h"
#include "options.h"
#include "pidfile.h"

namespace g {

server_parameters & cfg() noexcept;

resmtp::monitor & mon() noexcept;

resmtp::Log & log() noexcept;

resmtp::LogSpamhaus & logsph() noexcept;

PidFile & pid_file() noexcept;

const char * app_version() noexcept;

}