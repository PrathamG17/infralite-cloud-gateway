#include "db/sqlite3.h"
#include "db/static_file_repository.hpp"

StaticFileRepository::StaticFileRepository(DatabaseHandler* db) : m_pDB(db) {}

bool StaticFileRepository::CreateTable()
{
    std::string sql =
        "CREATE TABLE IF NOT EXISTS STATICFILE ("
        "FileID      INTEGER PRIMARY KEY AUTOINCREMENT,"
        "RouteID     INTEGER UNIQUE,"
        "FilePath    TEXT NOT NULL,"
        "ContentType TEXT,"
        "IsActive    INTEGER DEFAULT 1,"
        "FOREIGN KEY(RouteID) REFERENCES MOCKROUTE(RouteID)"
        ");";

    return m_pDB->Execute(sql) &&
        m_pDB->EncryptLegacyTextColumn("STATICFILE", "FileID", "FilePath");
}

bool StaticFileRepository::AddFile(int routeId, const std::string& filePath, const std::string& contentType)
{
    sqlite3_stmt* stmt = nullptr;
    const std::string encryptedFilePath = m_pDB->EncryptSensitive(filePath);

    const char* sql = "INSERT OR REPLACE INTO STATICFILE (RouteID, FilePath, ContentType, IsActive) VALUES (?, ?, ?, 1);";

    if (sqlite3_prepare_v2(m_pDB->GetDB(), sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_int (stmt, 1, routeId);
    sqlite3_bind_text(stmt, 2, encryptedFilePath.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, contentType.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 4, 1);

    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);

    return ok;
}

std::vector<StaticFile> StaticFileRepository::GetFiles()
{
    sqlite3_stmt* stmt = nullptr;
    std::vector<StaticFile> files;

    const char* sql = "SELECT FileID, RouteID, FilePath, ContentType, IsActive FROM STATICFILE WHERE IsActive=1;";

    if (sqlite3_prepare_v2(m_pDB->GetDB(), sql, -1, &stmt, nullptr) != SQLITE_OK)
        return files;

    while (sqlite3_step(stmt) == SQLITE_ROW) 
    {
        StaticFile f;
        f.fileId = sqlite3_column_int (stmt, 0);
        f.routeId = sqlite3_column_int (stmt, 1);
        const auto* filePath = sqlite3_column_text(stmt, 2);
        f.filePath = m_pDB->DecryptSensitive(filePath
            ? reinterpret_cast<const char*>(filePath) : "");
        f.contentType = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        f.isActive = sqlite3_column_int (stmt, 4);
        files.push_back(f);
    }

    sqlite3_finalize(stmt);
    return files;
}

bool StaticFileRepository::RemoveFile(int fileId)
{
    sqlite3_stmt* stmt = nullptr;

    const char* sql = "UPDATE STATICFILE SET IsActive=0 WHERE FileID=?;";

    if (sqlite3_prepare_v2(m_pDB->GetDB(), sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_int(stmt, 1, fileId);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);

    return ok;
}
