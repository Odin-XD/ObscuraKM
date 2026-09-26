#pragma once

#include <ntddk.h>

namespace obscura {

namespace registry {
    NTSTATUS Initialize();
    void Cleanup();
}

namespace firmware {
    NTSTATUS Initialize();
    void Cleanup();
}

} 
