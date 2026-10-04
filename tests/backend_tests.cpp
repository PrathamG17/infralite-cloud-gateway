#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

#include <gtest/gtest.h>
#include <jwt-cpp/jwt.h>

#include "db/database_handler.hpp"
#include "db/access_log_repository.hpp"
#include "db/route_repository.hpp"
#include "db/static_file_repository.hpp"
#include "db/user_repository.hpp"
#include "server/file_handler.hpp"
#include "server/JwtHandler.hpp"
#include "server/SecurityManager.hpp"
#include "server/request.hpp"
#include "server/router.hpp"

namespace
{
    constexpr char JwtSecret[] = "infralite-test-secret-with-32-bytes";
    constexpr char EncryptionKey[] = "infralite-test-encryption-key-32-bytes";

    HttpRequest Request(const std::string& method, const std::string& path,
        const std::string& authorization = "")
    {
        std::string raw = method + " " + path + " HTTP/1.1\r\n";
        if (!authorization.empty())
            raw += "Authorization: " + authorization + "\r\n";
        raw += "\r\n";
        return HttpRequest::Parse(raw);
    }
}

TEST(SecurityTests, RejectsMissingExpiredAndInsufficientTokens)
{
    JWTVerifier verifier(JwtSecret, "HS256");
    SecurityManager security(verifier);
    Router router(nullptr);
    router.SetSecurityManager(&security);
    router.AddProtectedRoute("GET", "/secure/admin", [](const HttpRequest&) {
        return HttpResponse{};
    }, Role::Admin);

    EXPECT_EQ(router.RouteRequest(Request("GET", "/secure/admin")).iStatusCode, 401);

    const auto viewerToken = verifier.Generate({{"user", "viewer"}, {"role", "Viewer"}});
    EXPECT_EQ(router.RouteRequest(Request("GET", "/secure/admin", "Bearer " + viewerToken)).iStatusCode, 403);

    const auto expiredToken = jwt::create()
        .set_issuer("your-issuer")
        .set_expires_at(std::chrono::system_clock::now() - std::chrono::minutes(1))
        .set_payload_claim("user", jwt::claim(std::string("admin")))
        .set_payload_claim("role", jwt::claim(std::string("Admin")))
        .set_algorithm("HS256")
        .sign(jwt::algorithm::hs256{JwtSecret});
    EXPECT_EQ(router.RouteRequest(Request("GET", "/secure/admin", "Bearer " + expiredToken)).iStatusCode, 401);

    const auto adminToken = verifier.Generate({{"user", "admin"}, {"role", "Admin"}});
    EXPECT_EQ(router.RouteRequest(Request("GET", "/secure/admin", "Bearer " + adminToken)).iStatusCode, 200);
}

TEST(RouterTests, ExecutesHandlersOutsideRegistryLock)
{
    Router router(nullptr);
    std::atomic<int> active{0};
    std::atomic<int> maximumActive{0};
    router.AddRoute("GET", "/parallel", [&active, &maximumActive](const HttpRequest&) {
        const int current = ++active;
        int observed = maximumActive.load();
        while (current > observed && !maximumActive.compare_exchange_weak(observed, current))
        {
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
        --active;
        return HttpResponse{};
    });

    std::thread first([&router] { router.RouteRequest(Request("GET", "/parallel")); });
    std::thread second([&router] { router.RouteRequest(Request("GET", "/parallel")); });
    first.join();
    second.join();
    EXPECT_EQ(maximumActive.load(), 2);
}

TEST(DatabaseTests, EncryptsAndDecryptsSensitiveRepositoryFields)
{
    DatabaseHandler database;
    database.SetEncryptionKey(EncryptionKey);
    ASSERT_TRUE(database.Open(":memory:"));

    UserRepository users(&database);
    RouteRepository routes(&database);
    StaticFileRepository files(&database);
    AccessLogRepository accessLogs(&database);
    ASSERT_TRUE(users.CreateTable());
    ASSERT_TRUE(routes.CreateTable());
    ASSERT_TRUE(files.CreateTable());
    ASSERT_TRUE(accessLogs.CreateTable());
    ASSERT_GT(users.AddUser("admin", "password-hash", "Admin"), 0);
    const int routeId = routes.AddRoute(1, "GET", "/private", 200, "sensitive response");
    ASSERT_GT(routeId, 0);
    ASSERT_TRUE(files.AddFile(routeId, "private/document.txt", "text/plain"));
    ASSERT_TRUE(accessLogs.AddLog("GET", "/private", 200, 4, "192.0.2.1", "test-agent"));

    const auto storedUsers = users.GetUsers();
    ASSERT_EQ(storedUsers.size(), 1u);
    EXPECT_EQ(storedUsers.front().passwordHash, "password-hash");
    const auto storedRoutes = routes.GetRoutes();
    ASSERT_EQ(storedRoutes.size(), 1u);
    EXPECT_EQ(storedRoutes.front().responseBody, "sensitive response");
    const auto storedFiles = files.GetFiles();
    ASSERT_EQ(storedFiles.size(), 1u);
    EXPECT_EQ(storedFiles.front().filePath, "private/document.txt");

    sqlite3_stmt* statement = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(database.GetDB(),
        "SELECT PasswordHash FROM USER LIMIT 1", -1, &statement, nullptr), SQLITE_OK);
    ASSERT_EQ(sqlite3_step(statement), SQLITE_ROW);
    const auto* encryptedValue = reinterpret_cast<const char*>(sqlite3_column_text(statement, 0));
    ASSERT_NE(encryptedValue, nullptr);
    EXPECT_EQ(std::string(encryptedValue).rfind("enc:v1:", 0), 0u);
    sqlite3_finalize(statement);

    ASSERT_EQ(sqlite3_prepare_v2(database.GetDB(),
        "SELECT Path, ClientIP, UserAgent FROM ACCESSLOG LIMIT 1", -1, &statement, nullptr), SQLITE_OK);
    ASSERT_EQ(sqlite3_step(statement), SQLITE_ROW);
    for (int column = 0; column < 3; ++column)
    {
        const auto* value = reinterpret_cast<const char*>(sqlite3_column_text(statement, column));
        ASSERT_NE(value, nullptr);
        EXPECT_EQ(std::string(value).rfind("enc:v1:", 0), 0u);
    }
    sqlite3_finalize(statement);
}

TEST(FileHandlerTests, RejectsPathsOutsideStaticRoot)
{
    const auto tempRoot = std::filesystem::temp_directory_path() / "infralite-file-handler-test";
    const auto staticRoot = tempRoot / "static";
    std::filesystem::create_directories(staticRoot);
    {
        std::ofstream outside(tempRoot / "secret.txt");
        outside << "not public";
    }

    FileHandler handler(staticRoot.string());
    const auto response = handler.ServeFile("/../secret.txt");
    EXPECT_EQ(response.iStatusCode, 403);
    std::filesystem::remove_all(tempRoot);
}