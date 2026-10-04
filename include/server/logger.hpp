#pragma once
#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <string>

#include "spdlog/spdlog.h"

/** Severity values accepted by Logger::Log. */
enum class ELogLevel {INFO, WARNING, LOG_ERROR};

/** Writes leveled server messages to the configured log destination. */
class Logger
{
private:
    std::string sLogFilePath;

public:
    /** Creates a logger targeting a file path.
     * @param sPath Destination log file path.
     * @return No value.
     */
    Logger(const std::string& sPath);

    /** Releases logger resources. */
    ~Logger();

    /** Writes a message using the requested severity.
     * @param sMessage Message text to record.
     * @param eLevel Severity associated with the message.
     * @return No value.
     */
    void Log(const std::string& sMessage, ELogLevel eLevel);

    /** Checks whether the underlying logger is ready for use.
     * @return True when logging is initialized.
     */
    bool IsReady() const;
};

#endif
