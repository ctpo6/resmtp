#pragma once

#include "log.h"
#include "monitor.h"
#include "options.h"
#include "pidfile.h"

namespace g {

server_parameters & cfg() noexcept;

resmtp::monitor & mon() noexcept;

resmtp::logger & log() noexcept;

PidFile & pid_file() noexcept;

const char * app_version() noexcept;

}