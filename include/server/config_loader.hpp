#pragma once
#ifndef CONFIG_LOADER_HPP
#define CONFIG_LOADER_HPP

#include <string>
#include <vector>

#include "Logger.hpp"

/** Configuration-file representation of a static response route. */
struct RouteDef
{
    std::string sMethod;       
    std::string sPath;        
    std::string sResponseType; 
    std::string sResponseBody; 
    int iStatusCode = 200;          
    std::string sStatusText = "OK"; 
    int iDelayMs = 0;              
};

/** Reads route definitions from the server's JSON configuration file. */
class ConfigLoader
{
private:
    std::string sConfigPath;        
    std::vector<RouteDef> vRoutes;  

public:
    /** Creates a loader for a JSON route configuration.
     * @param sPath Path to the configuration file.
     * @return No value.
     */
    ConfigLoader(const std::string& sPath);

    /** Parses the configured route array and stores its definitions.
     * @param rLogger Logger used to report file or JSON errors.
     * @return True when the file has a valid routes array.
     */
    bool LoadConfig(Logger& rLogger);

    /** Returns the route definitions parsed by LoadConfig.
     * @return Copy of the current route-definition vector.
     */
    std::vector<RouteDef> GetRoutes() const;
};

#endif 
