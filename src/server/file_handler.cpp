#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>

#include "file_handler.hpp"

FileHandler::FileHandler(const std::string& sDir) : sRootDir(sDir) {}

std::string FileHandler::GetStaticDir() const
{
    return sRootDir;
}

HttpResponse FileHandler::ServeFile(const std::string& sPath) const
{
    HttpResponse rResponse;

    try
    {
        const std::filesystem::path root = std::filesystem::weakly_canonical(sRootDir);
        std::filesystem::path requested(sPath);
        while (!requested.empty() &&
            (requested.native().front() == '/' || requested.native().front() == '\\'))
            requested = requested.native().substr(1);

        const std::filesystem::path fullPath = std::filesystem::weakly_canonical(root / requested);
        const std::filesystem::path relativePath = fullPath.lexically_relative(root);
        // Canonicalization also resolves symlinks before enforcing root containment.
        if (relativePath.empty() || relativePath == "." || relativePath.is_absolute() ||
            *relativePath.begin() == "..")
        {
            rResponse.iStatusCode = 403;
            rResponse.sStatusText = "Forbidden";
            rResponse.eFormat = EResponseFormat::PLAIN;
            rResponse.sBody = "Access denied";
            return rResponse;
        }

        std::ifstream rFileStream(fullPath, std::ios::binary);
        if (!rFileStream.is_open())
        {
            rResponse.iStatusCode = 404;
            rResponse.sStatusText = "Not Found";
            rResponse.eFormat = EResponseFormat::PLAIN;
            rResponse.sBody = "File not found";
            return rResponse;
        }

        std::ostringstream rBuffer;
        rBuffer << rFileStream.rdbuf();
        rResponse.sBody = rBuffer.str();

        const std::string extension = fullPath.extension().string();
        if (extension == ".html" || extension == ".htm")
            rResponse.eFormat = EResponseFormat::HTML;
        else if (extension == ".json")
            rResponse.eFormat = EResponseFormat::JSON;
        else if (extension == ".xml")
            rResponse.eFormat = EResponseFormat::XML;
        else
            rResponse.eFormat = EResponseFormat::PLAIN;

        rResponse.iStatusCode = 200;
        rResponse.sStatusText = "OK";
        rResponse.mHeaders["Content-Length"] = std::to_string(rResponse.sBody.size());
    }
    catch (const std::exception& ex)
    {
        rResponse.iStatusCode = 500;
        rResponse.sStatusText = "Internal Server Error";
        rResponse.eFormat = EResponseFormat::PLAIN;
        rResponse.sBody = std::string("FileHandler exception: ") + ex.what();
    }

    return rResponse;
}