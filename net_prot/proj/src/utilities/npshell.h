#pragma once

#include "utils.h"

namespace np_shell
{
    struct sock_data
    {
        bool isolation_setup;
    };
    void setup_np_shell();
}