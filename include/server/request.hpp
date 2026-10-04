#pragma once
#ifndef REQUEST_HPP
#define REQUEST_HPP

#include <string>
#include <map>

/** Parsed HTTP request line, headers, and body. */
class HttpRequest
{
private:
    std::string sMethod;                        
    std::string sPath;                           
    std::string sHttpVersion;                    
    std::map<std::string, std::string> mHeaders; 
    std::string sBody;                          

public:
    /** Creates an empty request value. @return No value. */
    HttpRequest() = default;

    /** Parses a raw HTTP/1.x request into its component fields.
     * @param rawRequest Bytes received from the client socket.
     * @return Parsed request; missing fields remain empty.
     */
    static HttpRequest Parse(const std::string& rawRequest);

    /** Returns the request path.
     * @return Reference to the stored path string.
     */
    const std::string& GetPath()const;

    /** Returns the HTTP method.
     * @return Reference to the stored method string.
     */
    const std::string& GetMethod()const;

    /** Returns the parsed request body.
     * @return Reference to the stored body string.
     */
    const std::string& GetBody()const;

    /** Looks up a header without regard to header-name case.
     * @param key Header name to find.
     * @return Header value, or an empty string when absent.
     */
    std::string GetHeader(const std::string& key) const;
};

#endif
