#include "global.h"

namespace g {

resmtp::monitor & mon() noexcept
{
    static resmtp::monitor m;
    return m;
}

}
