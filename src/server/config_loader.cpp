#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

#include "logger.hpp"
#include "config_loader.hpp"

using json = nlohmann::json;

ConfigLoader::ConfigLoader(const std::string& sPath) : sConfigPath(sPath), vRoutes() {}

bool ConfigLoader::LoadConfig(Logger& rLogger)
{
    try
    {
        std::ifstream rFileStream(sConfigPath);
        if (!rFileStream.is_open())
        {
            rLogger.Log("ConfigLoader: Failed to open file " + sConfigPath, ELogLevel::LOG_ERROR);
            return false;
        }

        json jConfig;
        rFileStream >> jConfig;

        if (!jConfig.contains("routes") || !jConfig["routes"].is_array())
        {
            rLogger.Log("ConfigLoader: Invalid config structure, 'routes' array missing.", ELogLevel::LOG_ERROR);
            return false;
        }

        for (const auto& jRoute : jConfig["routes"])
        {
            RouteDef rDef;

            if (jRoute.contains("method"))
                rDef.sMethod = jRoute["method"].get<std::string>();

            if (jRoute.contains("path"))
                rDef.sPath = jRoute["path"].get<std::string>();

            if (jRoute.contains("responseType"))
                rDef.sResponseType = jRoute["responseType"].get<std::string>();

            if (jRoute.contains("responseBody"))
                rDef.sResponseBody = jRoute["responseBody"].get<std::string>();

            if (jRoute.contains("status"))
                rDef.iStatusCode = jRoute["status"].get<int>();

            if (jRoute.contains("statusText"))
                rDef.sStatusText = jRoute["statusText"].get<std::string>();

            if (jRoute.contains("delayMs"))
                rDef.iDelayMs = jRoute["delayMs"].get<int>();

            vRoutes.push_back(rDef);
        }

        return true;                    
    }
    catch (const std::exception& ex)
    {
        rLogger.Log("ConfigLoader: Exception during LoadConfig -> " + static_cast<std::string>(ex.what()), ELogLevel::LOG_ERROR);
        return false;
    }
}

std::vector<RouteDef> ConfigLoader::GetRoutes() const
{
    return vRoutes;
}
