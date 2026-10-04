#pragma once
#ifndef ROUTER_HPP
#define ROUTER_HPP

#include <map>
#include <mutex>
#include <string>
#include <functional>
#include <utility>
#include <vector>

#include "logger.hpp"
#include "request.hpp"
#include "response.hpp"
#include "file_handler.hpp"
#include "config_loader.hpp"
#include "SecurityManager.hpp"

/** Thread-safe registry that resolves HTTP method/path pairs to handlers.
 * Protected routes are authenticated and authorized before handler invocation.
 */
class Router
{
private:
    /** Handler and authorization metadata copied out of the registry lock per request. */
    struct RouteEntry
    {
        std::function<HttpResponse(const HttpRequest&)> handler;
        bool protectedRoute = false;
        Role requiredRole = Role::Viewer;
    };

    std::map<std::string, RouteEntry> mRoutes;
    std::map<std::string, std::pair<int,int>> mSimErrors;
    mutable std::mutex mMutex;
    FileHandler* pFileHandler;
    SecurityManager* pSecurityManager = nullptr;

public:
    /** Constructs a router with an optional static-file fallback.
     * @param pHandler File handler used for otherwise-unmatched GET requests.
     * @return No value.
     */
    Router(FileHandler* pHandler);

    /** Sets the security manager used for protected routes.
     * @param securityManager Manager that verifies bearer tokens and roles.
     * @return No value.
     */
    void SetSecurityManager(SecurityManager* securityManager);

    /** Adds or replaces a public route handler.
     * @param sMethod HTTP method for the route.
     * @param sPath Exact URL path for the route.
     * @param fnHandler Callback that creates the response.
     * @return No value.
     */
    void AddRoute(const std::string& sMethod, const std::string& sPath, std::function<HttpResponse(const HttpRequest&)> fnHandler);

    /** Adds or replaces a route protected by a minimum role.
     * @param sMethod HTTP method for the route.
     * @param sPath Exact URL path for the route.
     * @param fnHandler Callback invoked after authorization succeeds.
     * @param requiredRole Minimum role allowed to invoke the callback.
     * @return No value.
     */
    void AddProtectedRoute(const std::string& sMethod, const std::string& sPath,
        std::function<HttpResponse(const HttpRequest&)> fnHandler, Role requiredRole);

    /** Checks whether the exact method/path pair is registered.
     * @param sMethod HTTP method to find.
     * @param sPath Exact URL path to find.
     * @return True when the route is registered.
     */
    bool HasRoute(const std::string& sMethod, const std::string& sPath) const;

    /** Returns method/path pairs for the current route registry.
     * @return A snapshot of registered route keys.
     */
    std::vector<std::pair<std::string, std::string>> ListRoutes() const;

    /** Removes a route and its error simulation entry.
     * @param sMethod HTTP method of the route.
     * @param sPath Exact URL path of the route.
     * @return No value.
     */
    void RemoveRoute(const std::string& sMethod, const std::string& sPath);

    /** Configures a simulated status and delay for a route key.
     * @param sMethod HTTP method to match.
     * @param sPath Exact URL path to match.
     * @param iStatusCode Status code to return or simulate.
     * @param iDelayMs Delay before the simulated response, in milliseconds.
     * @return No value.
     */
    void SimulateError(const std::string& sMethod, const std::string& sPath, int iStatusCode, int iDelayMs);

    /** Removes a simulated error for a route key.
     * @param sMethod HTTP method to match.
     * @param sPath Exact URL path to match.
     * @return No value.
     */
    void ResetSimulation(const std::string& sMethod, const std::string& sPath);

    /** Loads configured routes from a parsed configuration object.
     * @param rConfig Source of route definitions.
     * @param rLogger Logger for load failures.
     * @return No value.
     */
    void LoadRoutes(const ConfigLoader& rConfig, Logger& rLogger);

    /** Resolves a request, applies route security, and invokes its handler.
     * @param request Parsed HTTP request to dispatch.
     * @return Handler response, authorization error, static-file response, or 404.
     */
    HttpResponse RouteRequest(const HttpRequest& request);

    /** Maps a configured response-type name to the response format enum.
     * @param sType Configured type such as JSON, HTML, or XML.
     * @return Matching response format, or PLAIN when unrecognized.
     */
    EResponseFormat StringToFormat(const std::string& sType);
};

#endif
