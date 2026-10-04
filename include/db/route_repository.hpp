#pragma once

#include <string>
#include <vector>

#include "database_handler.hpp"

/** Database representation of a configured or dynamic HTTP route. */
struct Route
{
    int routeId;
    int createdBy;
    std::string method;
    std::string path;
    int responseStatus;
    std::string responseBody;
    bool isActive;
};

/** Creates, reads, updates, and soft-deletes persistent route definitions. */
class RouteRepository
{
    private:
        DatabaseHandler* m_pDB;

    public:
        /** Binds the repository to an open database handler.
         * @param db Database connection and encryption service.
         * @return No value.
         */
        RouteRepository(DatabaseHandler* db);

        /** Creates the route table and migrates stored response bodies.
         * @return True when schema creation and migration succeed.
         */
        bool CreateTable();

        /** Persists a new route with an encrypted response body.
         * @param userId User that created the route.
         * @param method Supported HTTP method.
         * @param path Exact route path.
         * @param status HTTP status returned by the route.
         * @param body Response payload to store.
         * @return New route ID, or -1 when insertion fails.
         */
        int  AddRoute(int userId, const std::string& method, const std::string& path, int status, const std::string& body);

        /** Updates a persisted route and encrypts its replacement response body.
         * @param routeId Route record to update.
         * @param method Replacement HTTP method.
         * @param path Replacement route path.
         * @param status Replacement response status.
         * @param body Replacement response payload.
         * @return True when SQLite executes the update successfully.
         */
        bool UpdateRoute(int routeId, const std::string& method, const std::string& path, int status, const std::string& body);

        /** Soft-deletes a route by marking it inactive.
         * @param routeId Route record to deactivate.
         * @return True when SQLite executes the update successfully.
         */
        bool DeleteRoute(int routeId);

        /** Reads active routes and decrypts their response bodies.
         * @return Active route records; an empty vector is returned on query failure.
         */
        std::vector<Route> GetRoutes();
};
