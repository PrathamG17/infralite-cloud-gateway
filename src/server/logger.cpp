#include <iostream>

#include "logger.hpp"
#include "spdlog/sinks/basic_file_sink.h"

Logger::Logger(const std::string& sPath) : sLogFilePath(sPath) 
{
    try 
    {
        auto file_logger = spdlog::basic_logger_mt("file_logger", sLogFilePath);

        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S] [%l] %v");
        spdlog::set_default_logger(file_logger);
        spdlog::flush_on(spdlog::level::info);
    }
    catch (const spdlog::spdlog_ex& ex) 
    {
        std::cerr << "Logger init failed: " << ex.what() << std::endl;
    }
}

Logger::~Logger() 
{
    spdlog::shutdown();
}

void Logger::Log(const std::string& sMessage, ELogLevel eLevel) 
{
    switch (eLevel) 
    {
        case ELogLevel::INFO:
            spdlog::info(sMessage);
            break;
    
        case ELogLevel::WARNING:
            spdlog::warn(sMessage);
            break;
    
        case ELogLevel::LOG_ERROR:
            spdlog::error(sMessage);
            break;
    }
}

bool Logger::IsReady() const 
{
    return true;
}
