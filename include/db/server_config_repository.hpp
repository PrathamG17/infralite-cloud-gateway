#pragma once

#include <vector>

#include "db/server_config.hpp"
#include "db/database_handler.hpp"

/** Stores and retrieves server configuration values in SQLite. */
class ServerConfigRepository
{
    private :
        DatabaseHandler* m_pDB;

    public :
        /** Binds the repository to an open database handler.
         * @param db Database connection used by this repository.
         * @return No value.
         */
        ServerConfigRepository(DatabaseHandler* db);

        /** Creates the server-configuration table if needed.
         * @return True when the schema is available.
         */
        bool CreateTable();

        /** Inserts or replaces a configuration value.
         * @param key Unique configuration key.
         * @param value Value to persist.
         * @param description Human-readable purpose of the setting.
         * @return True when SQLite completes the write.
         */
        bool SetConfig(const std::string& key, const std::string& value, const std::string& description);

        /** Reads one configuration value by key.
         * @param key Configuration key to look up.
         * @return Stored value, or an empty string when absent or unreadable.
         */
        std::string GetConfig(const std::string& key);

        /** Reads all configuration records.
         * @return Configuration records; an empty vector is returned on query failure.
         */
        std::vector<ServerConfig> GetAllConfigs();
};
