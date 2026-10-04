#include "SecurityManager.hpp"

SecurityManager::SecurityManager(const JWTVerifier& verifier): jwtVerifier(verifier) {}

bool SecurityManager::Authorize(const HttpRequest& request, Role requiredRole)
{
    const Role userRole = Authenticate(request);
    return HasRequiredRole(userRole, requiredRole);
}

Role SecurityManager::Authenticate(const HttpRequest& request)
{
    std::string token = request.GetHeader("Authorization");
    // Only the explicit Bearer scheme is accepted for API credentials.
    if (token.empty())
        return Role::Unknown;

    const std::string bearerPrefix = "Bearer ";
    if (token.rfind(bearerPrefix, 0) != 0)
        return Role::Unknown;
    token = token.substr(bearerPrefix.size());
    if (token.empty())
        return Role::Unknown;

    if (!jwtVerifier.Verify(token))
        return Role::Unknown;

    return ExtractRole(token);
}

bool SecurityManager::HasRequiredRole(Role userRole, Role requiredRole)
{
    if (userRole == Role::Unknown)
        return false;

    // Role ranks encode the project's Admin > QA > Viewer permission inheritance.
    const auto rank = [](Role role) {
        switch (role)
        {
            case Role::Admin: return 3;
            case Role::QA: return 2;
            case Role::Viewer: return 1;
            default: return 0;
        }
    };
    return rank(userRole) >= rank(requiredRole);
}

Role SecurityManager::ExtractRole(const std::string& token) 
{
    try
    {
        const auto claims = jwtVerifier.Decode(token);
        const auto it = claims.find("role");
        if (it == claims.end())
            return Role::Unknown;
        if (it->second == "Admin")
            return Role::Admin;
        if (it->second == "QA")
            return Role::QA;
        if (it->second == "Viewer")
            return Role::Viewer;
    }
    catch (...)
    {
    }
    return Role::Unknown;
}
