#pragma once
#include <map>
#include <string>

#include <jwt-cpp/jwt.h>
#include <picojson/picojson.h>

/** Creates and verifies HS256 JSON Web Tokens for server authentication. */
class JWTVerifier
{
private:
    std::string secretKey;
    std::string algorithm;

public:
    /** Initializes JWT signing and verification with a shared secret.
     * @param secret Secret key material supplied by deployment configuration.
     * @param algo Algorithm name; the implementation currently signs with HS256.
     * @return No value.
     */
    JWTVerifier(const std::string& secret, const std::string& algo);

    /** Signs string claims and adds the server issuer and two-hour expiry.
     * @param claims Application claims such as user and role.
     * @return Compact signed JWT.
     */
    std::string Generate(const std::map<std::string, std::string>& claims);

    /** Validates a token signature, issuer, algorithm, and expiration.
     * @param token Compact JWT to validate.
     * @return True only when the token is valid and has not expired.
     */
    bool Verify(const std::string& token);

    /** Decodes the application string claims from a token.
     * @param token Compact JWT to decode.
     * @return Map of supported application claim names and values.
     */
    std::map<std::string, std::string> Decode(const std::string& token);
};
