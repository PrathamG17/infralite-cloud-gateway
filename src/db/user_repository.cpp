#include "db/sqlite3.h"
#include "db/user_repository.hpp"

UserRepository::UserRepository(DatabaseHandler* db) : m_pDB(db) {}

bool UserRepository::CreateTable()
{
    std::string sql =
        "CREATE TABLE IF NOT EXISTS USER ("
        "UserID       INTEGER PRIMARY KEY AUTOINCREMENT,"
        "Username     TEXT UNIQUE NOT NULL,"
        "PasswordHash TEXT NOT NULL,"
        "Role         TEXT,"
        "CreatedAt    DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "IsActive     INTEGER DEFAULT 1"
        ");";

    return m_pDB->Execute(sql) &&
        m_pDB->EncryptLegacyTextColumn("USER", "UserID", "PasswordHash");
}

int UserRepository::AddUser(const std::string& username, const std::string& passwordHash, const std::string& role)
{
    sqlite3_stmt* stmt = nullptr;
    const std::string encryptedPasswordHash = m_pDB->EncryptSensitive(passwordHash);

    const char* sql = "INSERT INTO USER (Username, PasswordHash, Role) VALUES (?, ?, ?);";

    if (sqlite3_prepare_v2(m_pDB->GetDB(), sql, -1, &stmt, nullptr) != SQLITE_OK)
        return -1;

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, encryptedPasswordHash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, role.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) 
    {
        sqlite3_finalize(stmt);
        return -1;
    }

    int id = sqlite3_last_insert_rowid(m_pDB->GetDB());
    sqlite3_finalize(stmt);

    return id;
}

std::vector<User> UserRepository::GetUsers()
{
    std::vector<User> users;
    sqlite3_stmt* stmt = nullptr;

    const char* sql = "SELECT UserID, Username, PasswordHash, Role, CreatedAt, IsActive FROM USER WHERE IsActive = 1;";
        
    if (sqlite3_prepare_v2(m_pDB->GetDB(), sql, -1, &stmt, nullptr) != SQLITE_OK)
        return users;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) 
    {
        User u;
        u.userId = sqlite3_column_int (stmt, 0);
        u.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const auto* passwordHash = sqlite3_column_text(stmt, 2);
        u.passwordHash = m_pDB->DecryptSensitive(passwordHash
            ? reinterpret_cast<const char*>(passwordHash) : "");
        u.role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        u.createdAt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        u.isActive = sqlite3_column_int (stmt, 5);
        users.push_back(u);
    }

    sqlite3_finalize(stmt);

    return users;
}

bool UserRepository::UpdateUser(int userId, const std::string& role, const std::string& passwordHash)
{
    sqlite3_stmt* stmt = nullptr;
    const std::string encryptedPasswordHash = passwordHash == "unchanged"
        ? passwordHash : m_pDB->EncryptSensitive(passwordHash);
    const char* sql;

    if (passwordHash == "unchanged")
        sql = "UPDATE USER SET Role=? WHERE UserID=?;";
    else
        sql = "UPDATE USER SET Role=?, PasswordHash=? WHERE UserID=?;";

    if (sqlite3_prepare_v2(m_pDB->GetDB(), sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_text(stmt, 1, role.c_str(), -1, SQLITE_STATIC);

    if (passwordHash != "unchanged") 
    {
        sqlite3_bind_text(stmt, 2, encryptedPasswordHash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int (stmt, 3, userId);
    } 
    else
        sqlite3_bind_int(stmt, 2, userId);

    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);

    return ok;
}

bool UserRepository::DeleteUser(int userId)
{
    sqlite3_stmt* stmt = nullptr;

    const char* sql = "UPDATE USER SET IsActive=0 WHERE UserID=?;";

    if (sqlite3_prepare_v2(m_pDB->GetDB(), sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_int(stmt, 1, userId);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);

    return ok;
}
