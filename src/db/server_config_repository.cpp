#include "db/sqlite3.h"
#include "db/server_config_repository.hpp"

ServerConfigRepository::ServerConfigRepository(DatabaseHandler* db) : m_pDB(db) {}

bool ServerConfigRepository::CreateTable()
{
    std::string sql = 
        "CREATE TABLE IF NOT EXISTS SERVERCONFIG ("
        "ConfigID INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ConfigKey TEXT UNIQUE NOT NULL,"
        "ConfigValue TEXT,"
        "Description TEXT,"
        "ModifiedAt DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");";

    return m_pDB->Execute(sql);
}

bool ServerConfigRepository::SetConfig(const std::string& key, const std::string& value, const std::string& description)
{
    sqlite3_stmt* stmt = nullptr;

    const char* sql = "INSERT OR REPLACE INTO SERVERCONFIG (ConfigKey, ConfigValue, Description, ModifiedAt) VALUES  (?, ?, ?, CURRENT_TIMESTAMP);";

    if (sqlite3_prepare_v2(m_pDB->GetDB(), sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, description.c_str(), -1, SQLITE_STATIC);

    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);

    return success;
}

std::string ServerConfigRepository::GetConfig(const std::string& key)
{
    std::string value;
    sqlite3_stmt* stmt = nullptr;

    const char* sql = "SELECT ConfigValue FROM SERVERCONFIG WHERE ConfigKey=?;";

    if (sqlite3_prepare_v2(m_pDB->GetDB(), sql, -1, &stmt, nullptr) != SQLITE_OK)
        return value;

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) == SQLITE_ROW)
        value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));

    sqlite3_finalize(stmt);

    return value;
}

std::vector<ServerConfig> ServerConfigRepository::GetAllConfigs()
{
    sqlite3_stmt* stmt = nullptr;
    std::vector<ServerConfig> configs;

    const char* sql = "SELECT ConfigID, ConfigKey, ConfigValue, Description, ModifiedAt FROM SERVERCONFIG;";

    if (sqlite3_prepare_v2(m_pDB->GetDB(), sql, -1, &stmt, nullptr) != SQLITE_OK)
        return configs;

    while(sqlite3_step(stmt) == SQLITE_ROW)
    {
        ServerConfig c;

        c.configId = sqlite3_column_int(stmt, 0);
        c.configKey = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        c.configValue = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        c.description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        c.modifiedAt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));

        configs.push_back(c);
    }

    sqlite3_finalize(stmt);

    return configs;
}

