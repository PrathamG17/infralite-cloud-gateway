#include <sstream>
#include <iostream>
#include <cctype>

#include "request.hpp"

HttpRequest HttpRequest::Parse(const std::string& sRawRequest)
{
    HttpRequest rRequest;

    std::istringstream rStream(sRawRequest);
    std::string sRequestLine;

    if (std::getline(rStream, sRequestLine))
    {
        std::istringstream rLineStream(sRequestLine);

        rLineStream >> rRequest.sMethod;       
        rLineStream >> rRequest.sPath;         
        rLineStream >> rRequest.sHttpVersion; 
    }

    std::string sHeaderLine;
    while (std::getline(rStream, sHeaderLine))
    {
        if (sHeaderLine == "\r" || sHeaderLine.empty())
            break;

        if (!sHeaderLine.empty() && sHeaderLine.back() == '\r')
            sHeaderLine.pop_back();

        size_t iDelimiterPos = sHeaderLine.find(":");
        if (iDelimiterPos != std::string::npos)
        {
            std::string sKey = sHeaderLine.substr(0, iDelimiterPos);
            std::string sValue = sHeaderLine.substr(iDelimiterPos + 1);

            if (!sValue.empty() && sValue.front() == ' ')
                sValue.erase(0, 1);

            rRequest.mHeaders[sKey] = sValue;
        }
    }

    std::string sBodyContent;
    std::string sLine;
    while (std::getline(rStream, sLine))
    {
        if (!sLine.empty() && sLine.back() == '\r')
            sLine.pop_back();

        sBodyContent += sLine + "\n";
    }

    if (!sBodyContent.empty() && sBodyContent.back() == '\n')
        sBodyContent.pop_back();

    rRequest.sBody = sBodyContent;

    return rRequest;
}

const std::string& HttpRequest::GetPath()const
{
    return sPath;
}

const std::string& HttpRequest::GetMethod()const
{
    return sMethod;
}

const std::string& HttpRequest::GetBody()const
{
    return sBody;
}

std::string HttpRequest::GetHeader(const std::string& key) const
{
    auto toLower = [](std::string value) {
        for (char& character : value)
            character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
        return value;
    };
    const std::string requestedName = toLower(key);
    for (const auto& header : mHeaders)
        if (toLower(header.first) == requestedName)
            return header.second;

    return "";
}
