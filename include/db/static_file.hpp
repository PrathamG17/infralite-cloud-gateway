#pragma once

#include <string>

/** Persistent mapping between a route and a static file. */
struct StaticFile
{
    int fileId;
    int routeId;
    std::string filePath;
    std::string contentType;
    int isActive;
};

