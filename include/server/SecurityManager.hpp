#pragma once
#include <string>
#include "request.hpp"
#include "JwtHandler.hpp"

/** Authorization roles supported by the headless server. */
enum class Role { Admin, QA, Viewer, Unknown };

/** Validates bearer tokens and evaluates the role hierarchy for requests. */
class SecurityManager
{
private:
    JWTVerifier jwtVerifier;

public:
    /** Creates a manager backed by a JWT verifier.
     * @param verifier Verifier configured with the server signing secret.
     * @return No value.
     */
    SecurityManager(const JWTVerifier& verifier);

    /** Checks whether a request satisfies a minimum role requirement.
     * @param request Request containing the bearer token.
     * @param requiredRole Minimum role required for the operation.
     * @return True only when the token is valid and its role is sufficient.
     */
    bool Authorize(const HttpRequest& request, Role requiredRole);

    /** Authenticates a request and extracts its validated role.
     * @param request Request containing an Authorization bearer header.
     * @return Authenticated role, or Role::Unknown when authentication fails.
     */
    Role Authenticate(const HttpRequest& request);

    /** Compares roles using the Admin > QA > Viewer hierarchy.
     * @param userRole Role presented by the authenticated principal.
     * @param requiredRole Minimum role required by a route.
     * @return True when userRole grants requiredRole or greater privileges.
     */
    static bool HasRequiredRole(Role userRole, Role requiredRole);

    /** Reads the role claim from a signed token.
     * @param token Compact JWT to decode.
     * @return Role represented by the claim, or Role::Unknown if absent/invalid.
     */
    Role ExtractRole(const std::string& token);
};
