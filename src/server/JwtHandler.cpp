#include "JwtHandler.hpp"

#include <chrono>

JWTVerifier::JWTVerifier(const std::string& secret, const std::string& algo): secretKey(secret), algorithm(algo) {}

std::string JWTVerifier::Generate(const std::map<std::string, std::string>& claims)
{
    auto token = jwt::create()
        .set_issuer("your-issuer")
        .set_type("JWS")
        .set_expires_in(std::chrono::hours(2))
        .set_algorithm(algorithm);

    for (const auto& kv : claims) 
        token.set_payload_claim(kv.first, jwt::claim(kv.second));

    return token.sign(jwt::algorithm::hs256{ secretKey });
}

bool JWTVerifier::Verify(const std::string& token)
{
    try
    {
        auto decoded = jwt::decode(token);
        // Reject tokens without expiry so every accepted access token is time-bounded.
        if (!decoded.has_expires_at())
            return false;

        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{ secretKey })
            .with_issuer("your-issuer");

        verifier.verify(decoded);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

std::map<std::string, std::string> JWTVerifier::Decode(const std::string& token)
{
    std::map<std::string, std::string> claims;

    auto decoded = jwt::decode(token);
    for (const std::string& name : {std::string("user"), std::string("role")})
        if (decoded.has_payload_claim(name))
            claims[name] = decoded.get_payload_claim(name).as_string();

    return claims;
}
