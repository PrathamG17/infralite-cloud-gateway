#pragma once

#include <string>

#include "database_handler.hpp"

/** Persists request metadata with sensitive fields encrypted at rest. */
class AccessLogRepository
{
    private :
        DatabaseHandler *m_pDB;

    public :
        /** Binds the repository to an open database handler.
         * @param db Database connection and encryption service.
         * @return No value.
         */
        AccessLogRepository(DatabaseHandler* db);

        /** Creates the access-log table and migrates legacy sensitive values.
         * @return True when schema creation and migration succeed.
         */
        bool CreateTable();

        /** Adds one request record, encrypting path and client metadata.
         * @param method HTTP method received.
         * @param path Request path.
         * @param statusCode Response status code.
         * @param responseTime Request processing time in milliseconds.
         * @param clientIP Remote client IP address.
         * @param userAgent Client User-Agent header.
         * @return True when the row is inserted successfully.
         */
        bool AddLog(const std::string& method, const std::string& path, int statusCode, int responseTime, const std::string& clientIP, const std::string& userAgent);
};

