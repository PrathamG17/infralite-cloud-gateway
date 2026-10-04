#pragma once
#ifndef RESPONSE_HPP
#define RESPONSE_HPP

#include <map>
#include <string>

/** Content format used when no explicit Content-Type header is supplied. */
enum class EResponseFormat {HTML, JSON, XML, PLAIN};

/** Mutable HTTP status, headers, body, and wire-format representation. */
class HttpResponse
{
public:
    int iStatusCode;                             
    std::string sStatusText;                     
    std::map<std::string, std::string> mHeaders; 
    std::string sBody;                           
    EResponseFormat eFormat;                   

public:
    /** Initializes a successful plain-text response. @return No value. */
    HttpResponse();

    /** Serializes the response as an HTTP/1.1 message.
     * @return Status line, headers, separator, and body bytes.
     */
    std::string ToString() const;
};

#endif
