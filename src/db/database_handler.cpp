#include <iostream>
#include <cctype>
#include <stdexcept>
#include <utility>
#include <vector>

#include "db/database_handler.hpp"

DatabaseHandler::DatabaseHandler() : m_pDB(nullptr), m_pEncryption(nullptr) {}

DatabaseHandler::~DatabaseHandler()
{
    Close();
}

bool DatabaseHandler::Open(const std::string& sDBPath)
{
    int rc = sqlite3_open(sDBPath.c_str(), &m_pDB);

    if(rc)
    {
        std::cerr << "Cannot Open database\n";
        return false;
    }

    return true;
}

void DatabaseHandler::Close()
{
    if (m_pDB)
    {
        sqlite3_close(m_pDB);
        m_pDB = nullptr;
    }
}

bool DatabaseHandler::Execute(const std::string& sSQL)
{
    char* errMsg = nullptr;

    int rc = sqlite3_exec(m_pDB, sSQL.c_str(), nullptr, nullptr, &errMsg);

    if (rc != SQLITE_OK)
    {
        std::cerr << "SQL Error : " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }

    return true;
}

void DatabaseHandler::SetEncryptionKey(const std::string& keyMaterial)
{
    m_pEncryption = std::make_unique<FieldEncryption>(keyMaterial);
}

std::string DatabaseHandler::EncryptSensitive(const std::string& value) const
{
    if (!m_pEncryption)
        return value;
    return m_pEncryption->Encrypt(value);
}

std::string DatabaseHandler::DecryptSensitive(const std::string& value) const
{
    if (!m_pEncryption)
        return value;
    return m_pEncryption->Decrypt(value);
}

bool DatabaseHandler::EncryptLegacyTextColumn(const std::string& table,
    const std::string& idColumn, const std::string& valueColumn)
{
    const auto validIdentifier = [](const std::string& identifier) {
        if (identifier.empty())
            return false;
        for (unsigned char character : identifier)
            if (!std::isalnum(character) && character != '_')
                return false;
        return true;
    };
    if (!m_pEncryption)
        return true;
    if (!validIdentifier(table) || !validIdentifier(idColumn) || !validIdentifier(valueColumn))
        return false;

    // Validate identifiers before constructing SQL; values remain bound parameters.
    const std::string selectSql = "SELECT " + idColumn + ", " + valueColumn + " FROM " + table +
        " WHERE " + valueColumn + " IS NOT NULL;";
    sqlite3_stmt* selectStatement = nullptr;
    if (sqlite3_prepare_v2(m_pDB, selectSql.c_str(), -1, &selectStatement, nullptr) != SQLITE_OK)
        return false;

    std::vector<std::pair<sqlite3_int64, std::string>> legacyValues;
    int result = SQLITE_OK;
    while ((result = sqlite3_step(selectStatement)) == SQLITE_ROW)
    {
        const auto* value = sqlite3_column_text(selectStatement, 1);
        if (!value)
            continue;
        std::string plaintext = reinterpret_cast<const char*>(value);
        if (!FieldEncryption::IsEncrypted(plaintext))
            legacyValues.emplace_back(sqlite3_column_int64(selectStatement, 0), std::move(plaintext));
    }
    sqlite3_finalize(selectStatement);
    if (result != SQLITE_DONE)
        return false;

    const std::string updateSql = "UPDATE " + table + " SET " + valueColumn + "=? WHERE " + idColumn + "=?;";
    sqlite3_stmt* updateStatement = nullptr;
    if (sqlite3_prepare_v2(m_pDB, updateSql.c_str(), -1, &updateStatement, nullptr) != SQLITE_OK)
        return false;

    for (const auto& entry : legacyValues)
    {
        const std::string encrypted = m_pEncryption->Encrypt(entry.second);
        sqlite3_reset(updateStatement);
        sqlite3_clear_bindings(updateStatement);
        sqlite3_bind_text(updateStatement, 1, encrypted.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(updateStatement, 2, entry.first);
        if (sqlite3_step(updateStatement) != SQLITE_DONE)
        {
            sqlite3_finalize(updateStatement);
            return false;
        }
    }

    sqlite3_finalize(updateStatement);
    return true;
}

sqlite3* DatabaseHandler::GetDB()
{
    return m_pDB;
}

