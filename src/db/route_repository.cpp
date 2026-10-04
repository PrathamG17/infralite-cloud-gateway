#include <iostream>

#include "db/sqlite3.h"
#include "db/route_repository.hpp"

RouteRepository::RouteRepository(DatabaseHandler* db) : m_pDB(db) {}

bool RouteRepository::CreateTable()
{
    std::string sql =
        "CREATE TABLE IF NOT EXISTS MOCKROUTE ("
        "RouteID        INTEGER PRIMARY KEY AUTOINCREMENT,"
        "CreatedBy      INTEGER,"
        "Method         TEXT NOT NULL,"
        "Path           TEXT NOT NULL,"
        "ResponseStatus INTEGER,"
        "ResponseBody   TEXT,"
        "IsActive       INTEGER DEFAULT 1,"
        "CreatedAt      DATETIME DEFAULT CURRENT_TIMESTAMP,"
        "UNIQUE(Method, Path),"
        "CHECK(Method IN ('GET', 'POST', 'PUT', 'DELETE')),"
        "FOREIGN KEY(CreatedBy) REFERENCES USER(UserID)"
        ");";

    return m_pDB->Execute(sql) &&
        m_pDB->EncryptLegacyTextColumn("MOCKROUTE", "RouteID", "ResponseBody");
}

int RouteRepository::AddRoute(int userId, const std::string& method, const std::string& path, int status, const std::string& body)
{
    sqlite3_stmt* stmt = nullptr;
    const std::string encryptedBody = m_pDB->EncryptSensitive(body);

    const char* sql = "INSERT INTO MOCKROUTE (CreatedBy, Method, Path, ResponseStatus, ResponseBody) VALUES (?, ?, ?, ?, ?);";

    if (sqlite3_prepare_v2(m_pDB->GetDB(), sql, -1, &stmt, nullptr) != SQLITE_OK)
        return -1;

    sqlite3_bind_int (stmt, 1, userId);
    sqlite3_bind_text(stmt, 2, method.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, path.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int (stmt, 4, status);
    sqlite3_bind_text(stmt, 5, encryptedBody.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) 
    {
        sqlite3_finalize(stmt);
        return -1;
    }

    int id = sqlite3_last_insert_rowid(m_pDB->GetDB());
    sqlite3_finalize(stmt);

    return id;
}

std::vector<Route> RouteRepository::GetRoutes()
{
    std::vector<Route> routes;
    sqlite3_stmt* stmt = nullptr;

    const char* sql = "SELECT RouteID, Method, Path, ResponseStatus, ResponseBody, IsActive FROM MOCKROUTE WHERE IsActive=1;";

    if (sqlite3_prepare_v2(m_pDB->GetDB(), sql, -1, &stmt, nullptr) != SQLITE_OK)
        return routes;

    while (sqlite3_step(stmt) == SQLITE_ROW) 
    {
        Route r;
    
        r.routeId = sqlite3_column_int (stmt, 0);
        r.method = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        r.path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        r.responseStatus = sqlite3_column_int (stmt, 3);
        const auto* responseBody = sqlite3_column_text(stmt, 4);
        r.responseBody = m_pDB->DecryptSensitive(responseBody
            ? reinterpret_cast<const char*>(responseBody) : "");
        r.isActive = sqlite3_column_int (stmt, 5);
        routes.push_back(r);
    }

    sqlite3_finalize(stmt);

    return routes;
}

bool RouteRepository::UpdateRoute(int routeId, const std::string& method, const std::string& path, int status, const std::string& body)
{
    sqlite3_stmt* stmt = nullptr;
    const std::string encryptedBody = m_pDB->EncryptSensitive(body);
    const char* sql = "UPDATE MOCKROUTE SET Method=?, Path=?, ResponseStatus=?, ResponseBody=? WHERE RouteID=?;";

    if (sqlite3_prepare_v2(m_pDB->GetDB(), sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_text(stmt, 1, method.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 3, status);
    sqlite3_bind_text(stmt, 4, encryptedBody.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 5, routeId);

    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);

    return ok;
}

bool RouteRepository::DeleteRoute(int routeId)
{
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "UPDATE MOCKROUTE SET IsActive=0 WHERE RouteID=?;";

    if (sqlite3_prepare_v2(m_pDB->GetDB(), sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_int(stmt, 1, routeId);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);

    return ok;
}
