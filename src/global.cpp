#include "global.h"

namespace g {

resmtp::monitor & mon() noexcept
{
    static resmtp::monitor m;
    return m;
}

server_parameters & cfg() noexcept
{
    static server_parameters c;
    return c;
}

}
