#include <filesystem>
#include <cstdlib>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <algorithm>
#include <array>
#include <cctype>
#include <csignal>
#include <cmath>
#include <limits>
#include <vector>

#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#include "db/access_log_repository.hpp"
#include "db/database_handler.hpp"
#include "db/route_repository.hpp"
#include "db/server_config_repository.hpp"
#include "db/static_file_repository.hpp"
#include "db/user_repository.hpp"
#include "file_handler.hpp"
#include "JwtHandler.hpp"
#include "logger.hpp"
#include "router.hpp"
#include "SecurityManager.hpp"
#include "server.hpp"
#include "TLSContext.hpp"

namespace
{
    CServer* gServer = nullptr;

    std::string EnvironmentValue(const char* name)
    {
#ifdef _WIN32
        char* buffer = nullptr;
        size_t size = 0;
        if (_dupenv_s(&buffer, &size, name) != 0 || !buffer)
            return {};
        std::string value(buffer);
        std::free(buffer);
        return value;
#else
        const char* value = std::getenv(name);
        return value ? value : "";
#endif
    }

    std::filesystem::path FindProjectRoot()
    {
        auto current = std::filesystem::current_path();
        for (int depth = 0; depth < 5; ++depth)
        {
            if (std::filesystem::exists(current / "config") &&
                std::filesystem::exists(current / "static"))
                return current;

            if (current == current.root_path())
                break;
            current = current.parent_path();
        }
        return std::filesystem::current_path();
    }

    std::string LegacyPasswordHash(const std::string& password)
    {
        const std::string salt = "InfraLite$2026#MockServer";
        const std::string salted = salt + password + salt;
        unsigned long long hash = 14695981039346656037ULL;

        for (unsigned char value : salted)
        {
            hash ^= value;
            hash *= 1099511628211ULL;
        }

        std::ostringstream output;
        output << std::hex << hash;
        return output.str();
    }

    std::string ToHex(const unsigned char* bytes, size_t size)
    {
        static constexpr char digits[] = "0123456789abcdef";
        std::string output(size * 2, '\0');
        for (size_t index = 0; index < size; ++index)
        {
            output[index * 2] = digits[bytes[index] >> 4];
            output[index * 2 + 1] = digits[bytes[index] & 0x0f];
        }
        return output;
    }

    std::vector<unsigned char> FromHex(const std::string& value)
    {
        if (value.size() % 2 != 0)
            throw std::runtime_error("Malformed stored password hash.");
        auto nibble = [](char character) -> unsigned char {
            if (character >= '0' && character <= '9') return character - '0';
            if (character >= 'a' && character <= 'f') return character - 'a' + 10;
            if (character >= 'A' && character <= 'F') return character - 'A' + 10;
            throw std::runtime_error("Malformed stored password hash.");
        };
        std::vector<unsigned char> output(value.size() / 2);
        for (size_t index = 0; index < output.size(); ++index)
            output[index] = static_cast<unsigned char>(
                (nibble(value[index * 2]) << 4) | nibble(value[index * 2 + 1]));
        return output;
    }

    std::string HashPassword(const std::string& password)
    {
        constexpr int iterations = 210000;
        std::array<unsigned char, 16> salt{};
        std::array<unsigned char, 32> digest{};
        // A fresh salt and deliberately expensive PBKDF2 derivation limit offline guessing.
        if (password.size() > static_cast<size_t>(std::numeric_limits<int>::max()) ||
            RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1 ||
            PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                salt.data(), static_cast<int>(salt.size()), iterations, EVP_sha256(),
                static_cast<int>(digest.size()), digest.data()) != 1)
            throw std::runtime_error("Unable to hash password.");
        return "pbkdf2-sha256$" + std::to_string(iterations) + "$" +
            ToHex(salt.data(), salt.size()) + "$" + ToHex(digest.data(), digest.size());
    }

    bool VerifyPassword(const std::string& password, const std::string& storedHash)
    {
        const std::string prefix = "pbkdf2-sha256$";
        if (storedHash.rfind(prefix, 0) != 0)
            return LegacyPasswordHash(password) == storedHash;

        const size_t iterationsEnd = storedHash.find('$', prefix.size());
        const size_t saltEnd = iterationsEnd == std::string::npos
            ? std::string::npos : storedHash.find('$', iterationsEnd + 1);
        if (iterationsEnd == std::string::npos || saltEnd == std::string::npos)
            return false;

        try
        {
            const int iterations = std::stoi(storedHash.substr(prefix.size(), iterationsEnd - prefix.size()));
            const auto salt = FromHex(storedHash.substr(iterationsEnd + 1, saltEnd - iterationsEnd - 1));
            const auto expected = FromHex(storedHash.substr(saltEnd + 1));
            if (iterations < 100000 || iterations > 1000000 || salt.size() != 16 ||
                expected.size() != 32 || password.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
                return false;

            std::array<unsigned char, 32> actual{};
            if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                    salt.data(), static_cast<int>(salt.size()), iterations, EVP_sha256(),
                    static_cast<int>(actual.size()), actual.data()) != 1)
                return false;
            // Compare fixed-length digests in constant time to avoid timing leaks.
            return CRYPTO_memcmp(actual.data(), expected.data(), actual.size()) == 0;
        }
        catch (const std::exception&)
        {
            return false;
        }
    }

    std::string CanonicalRole(const std::string& role)
    {
        if (role == "admin" || role == "Admin")
            return "Admin";
        if (role == "qa" || role == "QA")
            return "QA";
        if (role == "viewer" || role == "Viewer")
            return "Viewer";
        return role;
    }

#ifdef _WIN32
    BOOL WINAPI ConsoleHandler(DWORD signal)
    {
        if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT ||
            signal == CTRL_BREAK_EVENT || signal == CTRL_SHUTDOWN_EVENT)
        {
            if (gServer != nullptr)
                gServer->Stop();
            return TRUE;
        }
        return FALSE;
    }
#else
    void ConsoleHandler(int signal)
    {
        if ((signal == SIGINT || signal == SIGTERM) && gServer != nullptr)
            gServer->Stop();
    }
#endif

    void AddBuiltInRoutes(Router& router)
    {
        router.AddRoute("GET", "/health", [](const HttpRequest&) {
            HttpResponse response;
            response.iStatusCode = 200;
            response.sStatusText = "OK";
            response.mHeaders["Content-Type"] = "application/json";
            response.sBody = R"({"status":"ok","service":"infralite-server"})";
            return response;
        });

        router.AddProtectedRoute("GET", "/namaskar", [](const HttpRequest&) {
            HttpResponse response;
            response.iStatusCode = 200;
            response.sStatusText = "OK";
            response.mHeaders["Content-Type"] = "text/html";
            response.sBody = "<h1>Namaskar!</h1>";
            return response;
        }, Role::Viewer);

        router.AddProtectedRoute("GET", "/json", [](const HttpRequest&) {
            HttpResponse response;
            response.iStatusCode = 200;
            response.sStatusText = "OK";
            response.mHeaders["Content-Type"] = "application/json";
            response.sBody = R"({"message":"Hello JSON"})";
            return response;
        }, Role::Viewer);

        router.AddProtectedRoute("POST", "/submit", [](const HttpRequest& request) {
            HttpResponse response;
            response.mHeaders["Content-Type"] = "text/plain";

            if (request.GetBody().empty() || request.GetBody() == "{}")
            {
                response.iStatusCode = 400;
                response.sStatusText = "Bad Request";
                response.sBody = "error: missing data";
            }
            else
            {
                response.iStatusCode = 200;
                response.sStatusText = "OK";
                response.sBody = "Data received: " + request.GetBody();
            }
            return response;
        }, Role::QA);
    }

    void AddLoginRoute(Router& router, UserRepository& users, JWTVerifier& verifier)
    {
        router.AddRoute("POST", "/login", [&users, &verifier](const HttpRequest& request) {
            HttpResponse response;
            response.mHeaders["Content-Type"] = "application/json";

            try
            {
                const auto body = nlohmann::json::parse(request.GetBody());
                const std::string username = body.value("username", "");
                const std::string password = body.value("password", "");

                for (const auto& user : users.GetUsers())
                {
                    if (user.username == username && VerifyPassword(password, user.passwordHash))
                    {
                        if (user.passwordHash.rfind("pbkdf2-sha256$", 0) != 0)
                            users.UpdateUser(user.userId, user.role, HashPassword(password));
                        const std::string role = CanonicalRole(user.role);
                        const std::string token = verifier.Generate({
                            {"user", user.username}, {"role", role}
                        });
                        response.iStatusCode = 200;
                        response.sBody = nlohmann::json{
                            {"token", token},
                            {"username", user.username},
                            {"role", role}
                        }.dump();
                        return response;
                    }
                }
            }
            catch (const std::exception&)
            {
                // Treat malformed credentials the same as invalid credentials.
            }

            response.iStatusCode = 401;
            response.sStatusText = "Unauthorized";
            response.sBody = R"({"error":"invalid credentials"})";
            return response;
        });
    }

    void AddSecureRoleRoutes(Router& router)
    {
        router.AddProtectedRoute("GET", "/secure/admin", [](const HttpRequest&) {
            HttpResponse response;
            response.mHeaders["Content-Type"] = "text/plain";
            response.sBody = "Welcome Admin! JWT verified.";
            return response;
        }, Role::Admin);

        router.AddProtectedRoute("GET", "/secure/qa", [](const HttpRequest&) {
            HttpResponse response;
            response.mHeaders["Content-Type"] = "text/plain";
            response.sBody = "Hello QA team! JWT verified.";
            return response;
        }, Role::QA);

        router.AddProtectedRoute("GET", "/secure/viewer", [](const HttpRequest&) {
            HttpResponse response;
            response.mHeaders["Content-Type"] = "text/plain";
            response.sBody = "Viewer access granted. JWT verified.";
            return response;
        }, Role::Viewer);
    }

    HttpResponse ApiError(int status, const std::string& statusText, const std::string& message)
    {
        HttpResponse response;
        response.iStatusCode = status;
        response.sStatusText = statusText;
        response.mHeaders["Content-Type"] = "application/json";
        response.sBody = nlohmann::json{{"error", message}}.dump();
        return response;
    }

    void AddRouteManagementApi(Router& router, RouteRepository& routes,
        UserRepository& users, JWTVerifier& verifier)
    {
        router.AddProtectedRoute("GET", "/api/routes", [&router](const HttpRequest&) {
            nlohmann::json routeList = nlohmann::json::array();
            for (const auto& route : router.ListRoutes())
                routeList.push_back({{"method", route.first}, {"path", route.second}});

            HttpResponse response;
            response.mHeaders["Content-Type"] = "application/json";
            response.sBody = routeList.dump();
            return response;
        }, Role::Viewer);

        router.AddProtectedRoute("POST", "/api/routes",
            [&router, &routes, &users, &verifier](const HttpRequest& request) {
                nlohmann::json body;
                try
                {
                    body = nlohmann::json::parse(request.GetBody());
                }
                catch (const std::exception&)
                {
                    return ApiError(400, "Bad Request", "request body must be valid JSON");
                }

                if (!body.is_object() || !body.contains("method") || !body["method"].is_string() ||
                    !body.contains("path") || !body["path"].is_string() ||
                    !body.contains("status") || !body["status"].is_number_integer() ||
                    !body.contains("responseBody") || !body["responseBody"].is_string())
                    return ApiError(400, "Bad Request", "method, path, integer status, and string responseBody are required");

                std::string method = body["method"].get<std::string>();
                std::transform(method.begin(), method.end(), method.begin(),
                    [](unsigned char value) { return static_cast<char>(std::toupper(value)); });
                const std::string path = body["path"].get<std::string>();
                const double statusNumber = body["status"].get<double>();
                const std::string responseBody = body["responseBody"].get<std::string>();
                if ((method != "GET" && method != "POST" && method != "PUT" && method != "DELETE") ||
                    path.empty() || path.front() != '/' || path.size() > 256 ||
                    path.find("..") != std::string::npos || path.find('?') != std::string::npos ||
                    statusNumber < 100 || statusNumber > 599 || responseBody.size() > 1024 * 1024 ||
                    std::floor(statusNumber) != statusNumber ||
                    std::any_of(path.begin(), path.end(), [](unsigned char character) {
                        return std::isspace(character) || std::iscntrl(character) || character == '\\';
                    }))
                    return ApiError(400, "Bad Request", "route fields are outside allowed limits");
                const int status = static_cast<int>(statusNumber);

                if (path.rfind("/api/", 0) == 0 || path.rfind("/secure/", 0) == 0 ||
                    router.HasRoute(method, path))
                    return ApiError(409, "Conflict", "route path is reserved or already registered");

                std::string token = request.GetHeader("Authorization");
                const std::string bearerPrefix = "Bearer ";
                if (token.rfind(bearerPrefix, 0) == 0)
                    token.erase(0, bearerPrefix.size());
                const auto claims = verifier.Decode(token);
                const auto userClaim = claims.find("user");
                if (userClaim == claims.end())
                    return ApiError(401, "Unauthorized", "token has no user identity");

                int userId = 0;
                for (const auto& user : users.GetUsers())
                    if (user.username == userClaim->second)
                    {
                        userId = user.userId;
                        break;
                    }
                if (userId == 0)
                    return ApiError(401, "Unauthorized", "token user is no longer active");

                const int routeId = routes.AddRoute(userId, method, path, status, responseBody);
                if (routeId < 0)
                    return ApiError(409, "Conflict", "route could not be persisted");

                router.AddProtectedRoute(method, path, [status, responseBody](const HttpRequest&) {
                    HttpResponse response;
                    response.iStatusCode = status;
                    response.sStatusText = "OK";
                    response.sBody = responseBody;
                    return response;
                }, method == "GET" ? Role::Viewer : Role::Admin);

                HttpResponse response;
                response.iStatusCode = 201;
                response.sStatusText = "Created";
                response.mHeaders["Content-Type"] = "application/json";
                response.sBody = nlohmann::json{
                    {"routeId", routeId}, {"method", method}, {"path", path}
                }.dump();
                return response;
            }, Role::Admin);

        router.AddProtectedRoute("PUT", "/api/routes",
            [&router, &routes](const HttpRequest& request) {
                nlohmann::json body;
                try
                {
                    body = nlohmann::json::parse(request.GetBody());
                }
                catch (const std::exception&)
                {
                    return ApiError(400, "Bad Request", "request body must be valid JSON");
                }
                if (!body.is_object() || !body.contains("routeId") || !body["routeId"].is_number_integer() ||
                    !body.contains("method") || !body["method"].is_string() ||
                    !body.contains("path") || !body["path"].is_string() ||
                    !body.contains("status") || !body["status"].is_number_integer() ||
                    !body.contains("responseBody") || !body["responseBody"].is_string())
                    return ApiError(400, "Bad Request", "routeId, method, path, integer status, and responseBody are required");

                const int routeId = body["routeId"].get<int>();
                std::string method = body["method"].get<std::string>();
                std::transform(method.begin(), method.end(), method.begin(),
                    [](unsigned char value) { return static_cast<char>(std::toupper(value)); });
                const std::string path = body["path"].get<std::string>();
                const double statusNumber = body["status"].get<double>();
                const std::string responseBody = body["responseBody"].get<std::string>();
                if (routeId <= 0 || (method != "GET" && method != "POST" && method != "PUT" && method != "DELETE") ||
                    path.empty() || path.front() != '/' || path.size() > 256 ||
                    path.find("..") != std::string::npos || path.find('?') != std::string::npos ||
                    path.rfind("/api/", 0) == 0 || path.rfind("/secure/", 0) == 0 ||
                    statusNumber < 100 || statusNumber > 599 || std::floor(statusNumber) != statusNumber ||
                    responseBody.size() > 1024 * 1024 ||
                    std::any_of(path.begin(), path.end(), [](unsigned char character) {
                        return std::isspace(character) || std::iscntrl(character) || character == '\\';
                    }))
                    return ApiError(400, "Bad Request", "route fields are outside allowed limits");
                const int status = static_cast<int>(statusNumber);

                const auto currentRoutes = routes.GetRoutes();
                const auto found = std::find_if(currentRoutes.begin(), currentRoutes.end(),
                    [routeId](const Route& route) { return route.routeId == routeId; });
                if (found == currentRoutes.end())
                    return ApiError(404, "Not Found", "dynamic route not found");
                if ((found->method != method || found->path != path) && router.HasRoute(method, path))
                    return ApiError(409, "Conflict", "route path is already registered");
                if (!routes.UpdateRoute(routeId, method, path, status, responseBody))
                    return ApiError(409, "Conflict", "route could not be updated in storage");

                router.RemoveRoute(found->method, found->path);
                router.AddProtectedRoute(method, path, [status, responseBody](const HttpRequest&) {
                    HttpResponse response;
                    response.iStatusCode = status;
                    response.sStatusText = "OK";
                    response.sBody = responseBody;
                    return response;
                }, method == "GET" ? Role::Viewer : Role::Admin);

                HttpResponse response;
                response.mHeaders["Content-Type"] = "application/json";
                response.sBody = nlohmann::json{
                    {"routeId", routeId}, {"method", method}, {"path", path}
                }.dump();
                return response;
            }, Role::Admin);

        router.AddProtectedRoute("DELETE", "/api/routes",
            [&router, &routes](const HttpRequest& request) {
                nlohmann::json body;
                try
                {
                    body = nlohmann::json::parse(request.GetBody());
                }
                catch (const std::exception&)
                {
                    return ApiError(400, "Bad Request", "request body must identify a route in JSON");
                }

                const auto currentRoutes = routes.GetRoutes();
                auto found = currentRoutes.end();
                if (body.is_object() && body.contains("routeId") && body["routeId"].is_number_integer())
                {
                    const int routeId = body["routeId"].get<int>();
                    found = std::find_if(currentRoutes.begin(), currentRoutes.end(),
                        [routeId](const Route& route) { return route.routeId == routeId; });
                }
                else if (body.is_object() && body.contains("method") && body["method"].is_string() &&
                    body.contains("path") && body["path"].is_string())
                {
                    std::string method = body["method"].get<std::string>();
                    std::transform(method.begin(), method.end(), method.begin(),
                        [](unsigned char value) { return static_cast<char>(std::toupper(value)); });
                    const std::string path = body["path"].get<std::string>();
                    found = std::find_if(currentRoutes.begin(), currentRoutes.end(),
                        [&method, &path](const Route& route) {
                            return route.method == method && route.path == path;
                        });
                }
                else
                    return ApiError(400, "Bad Request", "provide routeId or method and path");

                if (found == currentRoutes.end())
                    return ApiError(404, "Not Found", "dynamic route not found");
                if (!routes.DeleteRoute(found->routeId))
                    return ApiError(500, "Internal Server Error", "route could not be removed from storage");

                router.RemoveRoute(found->method, found->path);
                HttpResponse response;
                response.iStatusCode = 204;
                response.sStatusText = "No Content";
                response.sBody.clear();
                return response;
            }, Role::Admin);
    }

    void AddOAuthTokenRoute(Router& router, JWTVerifier& verifier)
    {
        router.AddRoute("POST", "/oauth/token", [&verifier](const HttpRequest& request) {
            const std::string configuredClientId = EnvironmentValue("OAUTH_CLIENT_ID");
            const std::string configuredClientSecret = EnvironmentValue("OAUTH_CLIENT_SECRET");
            if (configuredClientId.empty() || configuredClientSecret.size() < 32)
                return ApiError(503, "Service Unavailable", "OAuth client credentials are not configured");

            nlohmann::json body;
            try
            {
                body = nlohmann::json::parse(request.GetBody());
            }
            catch (const std::exception&)
            {
                return ApiError(400, "Bad Request", "request body must be valid JSON");
            }
            if (!body.is_object() || !body.contains("grant_type") || !body["grant_type"].is_string() ||
                body["grant_type"].get<std::string>() != "client_credentials")
                return ApiError(400, "Bad Request", "unsupported_grant_type");
            if (!body.contains("client_id") || !body["client_id"].is_string() ||
                !body.contains("client_secret") || !body["client_secret"].is_string())
                return ApiError(400, "Bad Request", "client_id and client_secret are required");

            const std::string clientId = body["client_id"].get<std::string>();
            const std::string clientSecret = body["client_secret"].get<std::string>();
            const std::string& expectedId = configuredClientId;
            const std::string& expectedSecret = configuredClientSecret;
            const bool validId = clientId.size() == expectedId.size() &&
                CRYPTO_memcmp(clientId.data(), expectedId.data(), expectedId.size()) == 0;
            const bool validSecret = clientSecret.size() == expectedSecret.size() &&
                CRYPTO_memcmp(clientSecret.data(), expectedSecret.data(), expectedSecret.size()) == 0;
            if (!validId || !validSecret)
                return ApiError(401, "Unauthorized", "invalid_client");

            const std::string configuredRole = EnvironmentValue("OAUTH_CLIENT_ROLE");
            const std::string role = configuredRole.empty() ? "QA" : configuredRole;
            if (role != "QA" && role != "Viewer")
                return ApiError(503, "Service Unavailable", "OAuth client role must be QA or Viewer");

            const std::string token = verifier.Generate({
                {"user", "oauth:" + clientId}, {"role", role}
            });
            HttpResponse response;
            response.mHeaders["Content-Type"] = "application/json";
            response.mHeaders["Cache-Control"] = "no-store";
            response.mHeaders["Pragma"] = "no-cache";
            response.sBody = nlohmann::json{
                {"access_token", token}, {"token_type", "Bearer"}, {"expires_in", 7200}
            }.dump();
            return response;
        });
    }
}

int main(int argc, char* argv[])
{
    const auto projectRoot = FindProjectRoot();
    const bool enableTls = argc > 1 && std::string(argv[1]) == "--https";
    std::filesystem::create_directories(projectRoot / "data");
    std::filesystem::create_directories(projectRoot / "logs");
    std::filesystem::create_directories(projectRoot / "static");

    Logger logger((projectRoot / "logs" / "InfraLite-Server.log").string());

    try
    {
        const std::string jwtSecret = EnvironmentValue("JWT_SECRET");
        if (jwtSecret.size() < 32)
            throw std::runtime_error("JWT_SECRET must be configured with at least 32 characters.");

        const std::string encryptionKey = EnvironmentValue("INFRALITE_ENCRYPTION_KEY");
        if (encryptionKey.size() < 32)
            throw std::runtime_error("INFRALITE_ENCRYPTION_KEY must be configured with at least 32 characters.");

        DatabaseHandler database;
        database.SetEncryptionKey(encryptionKey);
        if (!database.Open((projectRoot / "data" / "infralite.db").string()))
        {
            std::cerr << "Database open failed.\n";
            return 1;
        }

        ServerConfigRepository configRepository(&database);
        UserRepository userRepository(&database);
        RouteRepository routeRepository(&database);
        StaticFileRepository fileRepository(&database);
        AccessLogRepository logRepository(&database);

        if (!configRepository.CreateTable() || !userRepository.CreateTable() ||
            !routeRepository.CreateTable() || !fileRepository.CreateTable() ||
            !logRepository.CreateTable())
        {
            std::cerr << "Database schema initialization failed.\n";
            return 1;
        }

        if (userRepository.GetUsers().empty())
        {
            const std::string adminPassword = EnvironmentValue("INFRALITE_BOOTSTRAP_ADMIN_PASSWORD");
            if (adminPassword.size() < 12)
                throw std::runtime_error("Set INFRALITE_BOOTSTRAP_ADMIN_PASSWORD to at least 12 characters for first startup.");
            if (userRepository.AddUser("admin", HashPassword(adminPassword), "Admin") < 0)
                throw std::runtime_error("Unable to create bootstrap administrator.");

            const std::string qaPassword = EnvironmentValue("INFRALITE_BOOTSTRAP_QA_PASSWORD");
            if (!qaPassword.empty())
            {
                if (qaPassword.size() < 12 ||
                    userRepository.AddUser("qa_user", HashPassword(qaPassword), "QA") < 0)
                    throw std::runtime_error("INFRALITE_BOOTSTRAP_QA_PASSWORD must be at least 12 characters.");
            }

            const std::string viewerPassword = EnvironmentValue("INFRALITE_BOOTSTRAP_VIEWER_PASSWORD");
            if (!viewerPassword.empty())
            {
                if (viewerPassword.size() < 12 ||
                    userRepository.AddUser("viewer1", HashPassword(viewerPassword), "Viewer") < 0)
                    throw std::runtime_error("INFRALITE_BOOTSTRAP_VIEWER_PASSWORD must be at least 12 characters.");
            }

            logger.Log("Bootstrap users initialized from runtime credentials.", ELogLevel::INFO);
        }

        if (configRepository.GetConfig("PORT").empty())
            configRepository.SetConfig("PORT", "8080", "Server listening port");

        const int port = std::stoi(configRepository.GetConfig("PORT"));
        JWTVerifier verifier(jwtSecret, "HS256");
        SecurityManager securityManager(verifier);
        FileHandler fileHandler((projectRoot / "static").string());
        Router router(&fileHandler);
        router.SetSecurityManager(&securityManager);

        ConfigLoader configLoader((projectRoot / "config" / "routes.json").string());
        if (configLoader.LoadConfig(logger))
            router.LoadRoutes(configLoader, logger);
        AddBuiltInRoutes(router);
        AddLoginRoute(router, userRepository, verifier);
        AddSecureRoleRoutes(router);

        std::unordered_map<int, StaticFile> fileMap;
        for (const auto& file : fileRepository.GetFiles())
            fileMap[file.routeId] = file;

        for (const auto& route : routeRepository.GetRoutes())
        {
            if (router.HasRoute(route.method, route.path))
            {
                logger.Log("Skipping persisted route that conflicts with a built-in route: " +
                    route.method + " " + route.path, ELogLevel::WARNING);
                continue;
            }

            const auto file = fileMap.find(route.routeId);
            if (file != fileMap.end())
            {
                const StaticFile staticFile = file->second;
                router.AddProtectedRoute(route.method, route.path,
                    [&fileHandler, staticFile](const HttpRequest&) {
                        return fileHandler.ServeFile(staticFile.filePath);
                    }, route.method == "GET" ? Role::Viewer : Role::Admin);
            }
            else
            {
                const Role requiredRole = route.method == "GET"
                    ? Role::Viewer
                    : (route.path == "/submit" ? Role::QA : Role::Admin);
                router.AddProtectedRoute(route.method, route.path,
                    [route](const HttpRequest&) {
                        HttpResponse response;
                        response.iStatusCode = route.responseStatus;
                        response.sStatusText = "OK";
                        response.sBody = route.responseBody;
                        return response;
                    }, requiredRole);
            }
        }

        AddRouteManagementApi(router, routeRepository, userRepository, verifier);
    AddOAuthTokenRoute(router, verifier);

        TLSContext tls((projectRoot / "certs" / "server.crt").string(),
                       (projectRoot / "certs" / "server.key").string());
        TLSContext* tlsContext = nullptr;
        if (enableTls)
        {
            if (!std::filesystem::exists(projectRoot / "certs" / "server.crt") ||
                !std::filesystem::exists(projectRoot / "certs" / "server.key") || !tls.Init())
                throw std::runtime_error("HTTPS was requested but TLS certificates could not be loaded.");
            tlsContext = &tls;
            logger.Log("TLS initialized.", ELogLevel::INFO);
        }
        else
        {
            logger.Log("Starting HTTP server. Use --https to enable TLS.", ELogLevel::WARNING);
        }

        CServer server(port, router, logger, &logRepository, tlsContext);
        gServer = &server;
    #ifdef _WIN32
        SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    #else
        std::signal(SIGINT, ConsoleHandler);
        std::signal(SIGTERM, ConsoleHandler);
    #endif

        std::cout << "InfraLite server listening on port " << port << ".\n";
        std::cout << "Press Ctrl+C to stop.\n";
        server.Run();
        gServer = nullptr;
        return 0;
    }
    catch (const std::exception& exception)
    {
        logger.Log("Fatal server error: " + std::string(exception.what()), ELogLevel::LOG_ERROR);
        std::cerr << "Server failed: " << exception.what() << "\n";
        return 1;
    }
}