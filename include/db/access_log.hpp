#pragma once
#include <string>

/** Request metadata record stored by AccessLogRepository. */
struct AccessLog
{
    long long logId;
    std::string timestamp;
    std::string method;
    std::string path;
    int statusCode;
    int responseTime;
    std::string clientIP;
    std::string userAgent;
};
