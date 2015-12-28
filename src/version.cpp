
// should be defined in CMakeLists.txt
#ifndef RESMTP_VERSION
#define RESMTP_VERSION "unknown"
#endif

namespace g {

const char * app_version() noexcept
{
    return RESMTP_VERSION;
}

}