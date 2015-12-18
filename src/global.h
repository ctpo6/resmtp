#pragma once

#include "monitor.h"

namespace g {

resmtp::monitor & mon() noexcept;

const char * app_version() noexcept;

}