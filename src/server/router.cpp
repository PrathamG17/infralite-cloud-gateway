#include <thread>
#include <chrono>
#include <iostream>
#include <algorithm>
#include <cctype>

#include "router.hpp"

Router::Router(FileHandler* pHandler) : pFileHandler(pHandler) {}

void Router::SetSecurityManager(SecurityManager* securityManager)
{
    std::lock_guard<std::mutex> lock(mMutex);
    pSecurityManager = securityManager;
}

void Router::AddRoute(const std::string& sMethod, const std::string& sPath, std::function<HttpResponse(const HttpRequest&)> fnHandler)
{
    std::lock_guard<std::mutex> lock(mMutex);
    std::string sKey = sMethod + ":" + sPath;
    mRoutes[sKey] = {std::move(fnHandler), false, Role::Viewer};
}

void Router::AddProtectedRoute(const std::string& sMethod, const std::string& sPath,
    std::function<HttpResponse(const HttpRequest&)> fnHandler, Role requiredRole)
{
    std::lock_guard<std::mutex> lock(mMutex);
    mRoutes[sMethod + ":" + sPath] = {std::move(fnHandler), true, requiredRole};
}

bool Router::HasRoute(const std::string& sMethod, const std::string& sPath) const
{
    std::lock_guard<std::mutex> lock(mMutex);
    return mRoutes.find(sMethod + ":" + sPath) != mRoutes.end();
}

std::vector<std::pair<std::string, std::string>> Router::ListRoutes() const
{
    std::vector<std::pair<std::string, std::string>> routes;
    std::lock_guard<std::mutex> lock(mMutex);
    for (const auto& route : mRoutes)
    {
        const auto separator = route.first.find(':');
        routes.emplace_back(route.first.substr(0, separator), route.first.substr(separator + 1));
    }
    return routes;
}

void Router::RemoveRoute(const std::string& sMethod, const std::string& sPath)
{
    std::lock_guard<std::mutex> lock(mMutex);
    std::string sKey = sMethod + ":" + sPath;
    mRoutes.erase(sKey);
    mSimErrors.erase(sKey);
}

void Router::SimulateError(const std::string& sMethod, const std::string& sPath, int iStatusCode, int iDelayMs)
{
    std::lock_guard<std::mutex> lock(mMutex);
    std::string sKey = sMethod + ":" + sPath;
    mSimErrors[sKey] = {iStatusCode, iDelayMs};
}

void Router::ResetSimulation(const std::string& sMethod, const std::string& sPath)
{
    std::lock_guard<std::mutex> lock(mMutex);
    std::string sKey = sMethod + ":" + sPath;
    mSimErrors.erase(sKey);
}

void Router::LoadRoutes(const ConfigLoader& rConfig, Logger& rLogger)
{
    try 
    {
        const auto& vRoutes = rConfig.GetRoutes();
        for (const auto& rRoute : vRoutes) 
        {
            std::string sKey = rRoute.sMethod + ":" + rRoute.sPath;
            auto fnHandler = [rRoute, this](const HttpRequest&) -> HttpResponse {
                HttpResponse rResponse;
                
                if (rRoute.iDelayMs > 0)
                    std::this_thread::sleep_for(std::chrono::milliseconds(rRoute.iDelayMs));
                
                rResponse.iStatusCode = rRoute.iStatusCode;
                rResponse.sStatusText = rRoute.sStatusText;
                rResponse.eFormat = StringToFormat(rRoute.sResponseType);
                rResponse.sBody = rRoute.sResponseBody;
                
                return rResponse;
            };
            std::lock_guard<std::mutex> lock(mMutex);
            mRoutes[sKey] = {fnHandler, true, rRoute.sMethod == "GET" ? Role::Viewer : Role::Admin};
        }
    } 
    catch (const std::exception& ex) 
    {
        rLogger.Log("Router::LoadRoutes exception -> " + std::string(ex.what()), ELogLevel::LOG_ERROR);
    }
}

HttpResponse Router::RouteRequest(const HttpRequest& request)
{
    HttpResponse rResponse;
    try 
    {
        std::string sKey = request.GetMethod() + ":" + request.GetPath();
        RouteEntry route;
        bool foundRoute = false;
        bool simulate = false;
        int simulationCode = 0;
        int simulationDelay = 0;
        SecurityManager* securityManager = nullptr;
        {
            // Copy routing state while locked; never run application callbacks under this mutex.
            std::lock_guard<std::mutex> lock(mMutex);
            securityManager = pSecurityManager;
            const auto routeIt = mRoutes.find(sKey);
            if (routeIt != mRoutes.end())
            {
                route = routeIt->second;
                foundRoute = true;
            }
            const auto simIt = mSimErrors.find(sKey);
            if (simIt != mSimErrors.end())
            {
                simulate = true;
                simulationCode = simIt->second.first;
                simulationDelay = simIt->second.second;
            }
        }

        if (foundRoute && route.protectedRoute)
        {
            const Role userRole = securityManager
                ? securityManager->Authenticate(request)
                : Role::Unknown;
            if (userRole == Role::Unknown)
            {
                rResponse.iStatusCode = 401;
                rResponse.sStatusText = "Unauthorized";
                rResponse.mHeaders["Content-Type"] = "application/json";
                rResponse.sBody = R"({"error":"missing or invalid bearer token"})";
                return rResponse;
            }
            if ((userRole == Role::Viewer && request.GetMethod() != "GET") ||
                !SecurityManager::HasRequiredRole(userRole, route.requiredRole))
            {
                rResponse.iStatusCode = 403;
                rResponse.sStatusText = "Forbidden";
                rResponse.mHeaders["Content-Type"] = "application/json";
                rResponse.sBody = R"({"error":"insufficient role"})";
                return rResponse;
            }
        }
        else if (!foundRoute && pFileHandler && request.GetMethod() == "GET")
        {
            const Role userRole = securityManager
                ? securityManager->Authenticate(request)
                : Role::Unknown;
            if (userRole == Role::Unknown ||
                !SecurityManager::HasRequiredRole(userRole, Role::Viewer))
            {
                rResponse.iStatusCode = 401;
                rResponse.sStatusText = "Unauthorized";
                rResponse.mHeaders["Content-Type"] = "application/json";
                rResponse.sBody = R"({"error":"missing or invalid bearer token"})";
                return rResponse;
            }
        }

        if (simulate)
        {
            if (simulationDelay > 0)
                std::this_thread::sleep_for(std::chrono::milliseconds(simulationDelay));

            if (simulationCode == 200 && foundRoute)
                return route.handler(request);

            rResponse.iStatusCode = simulationCode;
            switch (simulationCode)
            {
                case 404: 
                    rResponse.sStatusText = "Not Found"; 
                    break;

                case 401: 
                    rResponse.sStatusText = "Unauthorized"; 
                    break;

                case 400: 
                    rResponse.sStatusText = "Bad Request"; 
                    break;

                default:  
                    rResponse.sStatusText = "Internal Server Error"; 
                    break;
            }

            rResponse.mHeaders["Content-Type"] = "text/html";
            rResponse.sBody = "<h1>" + std::to_string(simulationCode) + " " + rResponse.sStatusText + " (Simulated)</h1>";

            return rResponse;
        }

        if (foundRoute)
            return route.handler(request);

        if (pFileHandler != nullptr && request.GetMethod() == "GET")
            return pFileHandler->ServeFile(request.GetPath());

        rResponse.iStatusCode = 404;
        rResponse.sStatusText = "Not Found";
        rResponse.eFormat = EResponseFormat::PLAIN;
        rResponse.sBody = "Route not found: " + request.GetPath();
    } 
    catch (const std::exception& ex) 
    {
        rResponse.iStatusCode = 500;
        rResponse.sStatusText = "Internal Server Error";
        rResponse.eFormat = EResponseFormat::PLAIN;
        rResponse.sBody = std::string("Router exception: ") + ex.what();
    }

    return rResponse;
}

EResponseFormat Router::StringToFormat(const std::string& sType)
{
    std::string type = sType;
    std::transform(type.begin(), type.end(), type.begin(),
        [](unsigned char value) { return static_cast<char>(std::toupper(value)); });
    if (type == "JSON") return EResponseFormat::JSON;
    if (type == "HTML") return EResponseFormat::HTML;
    if (type == "XML")  return EResponseFormat::XML;
    return EResponseFormat::PLAIN;
}
