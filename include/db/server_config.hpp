#pragma once
#include <string>

/** Named server setting and its database metadata. */
struct ServerConfig
{
    int configId;
    std::string configKey;
    std::string configValue;
    std::string description;
    std::string modifiedAt;

};
