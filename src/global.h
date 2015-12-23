#pragma once

#include "monitor.h"
#include "options.h"

namespace g {

server_parameters & cfg() noexcept;

resmtp::monitor & mon() noexcept;

const char * app_version() noexcept;

}