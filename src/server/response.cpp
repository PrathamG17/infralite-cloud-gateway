#include <sstream>

#include "response.hpp"

HttpResponse::HttpResponse(): iStatusCode(200), sStatusText("OK"), mHeaders(), sBody(""), eFormat(EResponseFormat::PLAIN){}

std::string HttpResponse::ToString() const
{
    std::ostringstream rResponseStream;

    rResponseStream << "HTTP/1.1 " << iStatusCode << " " << sStatusText << "\r\n";

    const auto contentType = mHeaders.find("Content-Type");
    if (contentType != mHeaders.end())
        rResponseStream << "Content-Type: " << contentType->second << "\r\n";
    else switch (eFormat)
    {
        case EResponseFormat::HTML:
            rResponseStream << "Content-Type: text/html\r\n";
            break;
    
        case EResponseFormat::JSON:
            rResponseStream << "Content-Type: application/json\r\n";
            break;
    
        case EResponseFormat::XML:
            rResponseStream << "Content-Type: application/xml\r\n";
            break;
    
        case EResponseFormat::PLAIN:
        default:
            rResponseStream << "Content-Type: text/plain\r\n";
            break;
    }

    for (const auto& rHeader : mHeaders)
    {
        if (rHeader.first == "Content-Type")
            continue;
        rResponseStream << rHeader.first << ": " << rHeader.second << "\r\n";
    }

    rResponseStream << "\r\n";
    rResponseStream << sBody;

    return rResponseStream.str();
}
