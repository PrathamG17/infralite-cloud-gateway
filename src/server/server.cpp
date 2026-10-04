#include <chrono>
#include <cctype>
#include <algorithm>
#include <iostream>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "server.hpp"
#include "router.hpp"
#include "request.hpp"
#include "response.hpp"
#include "threadpool.hpp"
#include "TLSContext.hpp"

#include "db/access_log_repository.hpp"

#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif

namespace
{
    size_t ContentLength(const std::string& request, size_t headerEnd)
    {
        std::string headers = request.substr(0, headerEnd);
        std::string lowerHeaders = headers;
        for (char& value : lowerHeaders)
            value = static_cast<char>(std::tolower(static_cast<unsigned char>(value)));

        const std::string name = "content-length:";
        const size_t position = lowerHeaders.find(name);
        if (position == std::string::npos)
            return 0;

        size_t valueStart = position + name.size();
        while (valueStart < headers.size() && std::isspace(static_cast<unsigned char>(headers[valueStart])))
            ++valueStart;

        size_t valueEnd = headers.find('\r', valueStart);
        if (valueEnd == std::string::npos)
            valueEnd = headers.find('\n', valueStart);

        try
        {
            return std::stoul(headers.substr(valueStart, valueEnd - valueStart));
        }
        catch (...)
        {
            return 0;
        }
    }
}

CServer::CServer(int iPort, Router& rRouter, Logger& pLogger, AccessLogRepository* logRepo)
        : iPort(iPort), rRouter(rRouter), iServerFd(SocketPlatform::Invalid), bIsRunning(false),
            bSocketInitialized(false), rLogger(pLogger),
      m_pLogRepo(logRepo), m_pTLS(nullptr)
{
    rLogger.Log("Server object created on port " + std::to_string(iPort) + " (HTTP)", ELogLevel::INFO);
}

CServer::CServer(int iPort, Router& rRouter, Logger& pLogger, AccessLogRepository* logRepo, TLSContext* pTLS)
        : iPort(iPort), rRouter(rRouter), iServerFd(SocketPlatform::Invalid), bIsRunning(false),
            bSocketInitialized(false), rLogger(pLogger),
      m_pLogRepo(logRepo), m_pTLS(pTLS)
{
    rLogger.Log("Server object created on port " + std::to_string(iPort) + " (HTTPS)", ELogLevel::INFO);
}

CServer::~CServer()
{
    const auto serverSocket = iServerFd.exchange(SocketPlatform::Invalid);
    if (serverSocket != SocketPlatform::Invalid)
    {
        SocketPlatform::Close(serverSocket);
        rLogger.Log("Server socket closed.", ELogLevel::INFO);
    }
    if (bSocketInitialized)
        SocketPlatform::Cleanup();
    rLogger.Log("Server object destroyed.", ELogLevel::INFO);
}

void CServer::Run()
{
    InitSocket();

    bIsRunning = true;
    rLogger.Log("Server running on port " + std::to_string(iPort), ELogLevel::INFO);

    const unsigned int hardwareThreads = std::thread::hardware_concurrency();
    ThreadPool pool(std::max(2u, hardwareThreads));

    while (bIsRunning)
    {
        const auto clientSocket = AcceptClient();
        if (clientSocket == SocketPlatform::Invalid)
        {
            if (!bIsRunning)
                break;
            rLogger.Log("Failed to accept client connection.", ELogLevel::WARNING);
            continue;
        }

        pool.enqueue([this, clientSocket]() {
            HandleClient(clientSocket);
        });
    }

    const auto serverSocket = iServerFd.exchange(SocketPlatform::Invalid);
    if (serverSocket != SocketPlatform::Invalid)
        SocketPlatform::Close(serverSocket);
    rLogger.Log("Server stopped.", ELogLevel::INFO);
}

void CServer::Stop()
{
    bIsRunning = false;
    const auto serverSocket = iServerFd.exchange(SocketPlatform::Invalid);
    if (serverSocket != SocketPlatform::Invalid)
    {
        SocketPlatform::Shutdown(serverSocket);
        SocketPlatform::Close(serverSocket);
    }
    rLogger.Log("Stop signal received. Server loop will exit.", ELogLevel::INFO);
}

void CServer::InitSocket()
{
    // SocketPlatform hides process startup and option differences between Winsock and POSIX.
    int iResult = SocketPlatform::Startup();
    if (iResult != 0)
    {
        rLogger.Log("Socket startup failed with error: " + std::to_string(iResult), ELogLevel::LOG_ERROR);
        throw std::runtime_error("Socket startup failed");
    }
    bSocketInitialized = true;

    const auto serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == SocketPlatform::Invalid)
    {
        rLogger.Log("socket() failed with error: " + std::to_string(SocketPlatform::LastError()), ELogLevel::LOG_ERROR);
        SocketPlatform::Cleanup();
        bSocketInitialized = false;
        throw std::runtime_error("Socket creation failed");
    }
    iServerFd = serverSocket;

    rLogger.Log("Socket created successfully.", ELogLevel::INFO);

    int iOptVal = 1;
    iResult = SocketPlatform::SetReuseAddress(serverSocket, iOptVal);
    if (iResult != 0)
    {
        rLogger.Log("setsockopt() failed with error: " + std::to_string(SocketPlatform::LastError()), ELogLevel::LOG_ERROR);
        SocketPlatform::Close(serverSocket);
        iServerFd = SocketPlatform::Invalid;
        SocketPlatform::Cleanup();
        bSocketInitialized = false;
        throw std::runtime_error("setsockopt failed");
    }
    rLogger.Log("Socket options set successfully (SO_REUSEADDR).", ELogLevel::INFO);

    sockaddr_in service{};
    service.sin_family = AF_INET;              
    service.sin_addr.s_addr = INADDR_ANY;      
    service.sin_port = htons(iPort);          

    iResult = bind(serverSocket, reinterpret_cast<const sockaddr*>(&service), sizeof(service));
    if (iResult != 0)
    {
        rLogger.Log("bind() failed with error: " + std::to_string(SocketPlatform::LastError()), ELogLevel::LOG_ERROR);
        SocketPlatform::Close(serverSocket);
        iServerFd = SocketPlatform::Invalid;
        SocketPlatform::Cleanup();
        bSocketInitialized = false;
        throw std::runtime_error("bind failed");
    }
    rLogger.Log("Socket bound successfully to port " + std::to_string(iPort), ELogLevel::INFO);

    iResult = listen(serverSocket, SOMAXCONN);
    if (iResult != 0)
    {
        rLogger.Log("listen() failed with error: " + std::to_string(SocketPlatform::LastError()), ELogLevel::LOG_ERROR);
        SocketPlatform::Close(serverSocket);
        iServerFd = SocketPlatform::Invalid;
        SocketPlatform::Cleanup();
        bSocketInitialized = false;
        throw std::runtime_error("listen failed");
    }
    rLogger.Log("Server is now listening on port " + std::to_string(iPort), ELogLevel::INFO);
}

SocketPlatform::Handle CServer::AcceptClient() const
{
    sockaddr_in clientInfo{};
    SocketPlatform::Length clientInfoSize = sizeof(clientInfo);

    const auto clientSocket = accept(iServerFd.load(), reinterpret_cast<sockaddr*>(&clientInfo), &clientInfoSize);
    if (clientSocket == SocketPlatform::Invalid)
    {
        rLogger.Log("accept() failed with error: " + std::to_string(SocketPlatform::LastError()), ELogLevel::LOG_ERROR);
        return SocketPlatform::Invalid;
    }
    rLogger.Log("Client connected.", ELogLevel::INFO);
    return clientSocket;
}

void CServer::HandleClient(SocketPlatform::Handle iClientFd)
{
    SSL* ssl = nullptr;

    try
    {
        auto startTime = std::chrono::high_resolution_clock::now();

        std::string sRawRequest;

        if (m_pTLS && m_pTLS->GetCTX()) 
        {
            rLogger.Log("Starting TLS handshake.", ELogLevel::INFO);
            SocketPlatform::SetReceiveTimeout(iClientFd, 10000);
            ssl = SSL_new(m_pTLS->GetCTX());
            SSL_set_fd(ssl, (int)iClientFd);
            const int handshakeResult = SSL_accept(ssl);
            if (handshakeResult <= 0) 
            {
                ERR_print_errors_fp(stderr);
                rLogger.Log("TLS handshake failed with OpenSSL error " +
                    std::to_string(SSL_get_error(ssl, handshakeResult)),
                    ELogLevel::WARNING);
                SSL_free(ssl);
                SocketPlatform::Close(iClientFd);
                return;
            }
            rLogger.Log("TLS handshake completed.", ELogLevel::INFO);
            sRawRequest = ReadRequestSSL(ssl);
        } 
        else 
            sRawRequest = ReadRequest(iClientFd);

        if (sRawRequest.empty()) 
        {
            rLogger.Log("Empty request received.", ELogLevel::WARNING);
            if (ssl) SSL_free(ssl);
            SocketPlatform::Close(iClientFd);
            return;
        }

        HttpRequest rRequest   = HttpRequest::Parse(sRawRequest);
        HttpResponse rResponse = rRouter.RouteRequest(rRequest);

        rResponse.mHeaders["Content-Length"] = std::to_string(rResponse.sBody.size());

        if (m_pLogRepo) 
        {
            sockaddr_in clientAddr;
            SocketPlatform::Length len = sizeof(clientAddr);
            getpeername(iClientFd, reinterpret_cast<sockaddr*>(&clientAddr), &len);
        
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &clientAddr.sin_addr, ip, INET_ADDRSTRLEN);
            std::string userAgent = rRequest.GetHeader("User-Agent");
            
            auto endTime = std::chrono::high_resolution_clock::now();
            
            int responseTime = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
            m_pLogRepo->AddLog(rRequest.GetMethod(), rRequest.GetPath(),rResponse.iStatusCode, responseTime, ip, userAgent);
        }

        if (ssl)
            SendResponseSSL(ssl, rResponse);
        else
            SendResponse(iClientFd, rResponse);
    }
    catch (const std::exception& rEx) 
    {
        rLogger.Log("Exception in HandleClient: " + std::string(rEx.what()), ELogLevel::WARNING);
        
        HttpResponse rErrorResp;
        rErrorResp.iStatusCode = 500;
        rErrorResp.sStatusText = "Internal Server Error";
        rErrorResp.sBody = "<h1>500 Internal Server Error</h1>";
        rErrorResp.mHeaders["Content-Type"]   = "text/html";
        rErrorResp.mHeaders["Content-Length"] = std::to_string(rErrorResp.sBody.size());
        
        if (ssl) 
            SendResponseSSL(ssl, rErrorResp);
        else     
            SendResponse(iClientFd, rErrorResp);
    }

    if (ssl) 
    { 
        SSL_shutdown(ssl); 
        SSL_free(ssl); 
    }

    SocketPlatform::Close(iClientFd);
}

std::string CServer::ReadRequest(SocketPlatform::Handle iClientFd)
{
    const int BUFFER_SIZE = 4096;
    char buffer[BUFFER_SIZE];
    std::string request;

    while (true)
    {
        int iResult = recv(iClientFd, buffer, BUFFER_SIZE, 0);
        if (iResult < 0)
        {
            rLogger.Log("recv() failed with error: " + std::to_string(SocketPlatform::LastError()), ELogLevel::LOG_ERROR);
            return "";
        }
        if (iResult == 0)
        {
            rLogger.Log("Client disconnected.", ELogLevel::INFO);
            return request;
        }

        request.append(buffer, iResult);
        const size_t headerEnd = request.find("\r\n\r\n");
        if (headerEnd == std::string::npos)
            continue;

        const size_t bodyStart = headerEnd + 4;
        if (request.size() >= bodyStart + ContentLength(request, headerEnd))
            break;
    }

    rLogger.Log("Raw HTTP request received:\n" + request, ELogLevel::INFO);
    return request;
}

void CServer::SendResponse(SocketPlatform::Handle iClientFd, const HttpResponse& rResponse)
{
    std::string sRawResponse = rResponse.ToString();

    int iTotalSent = 0;
    int iResponseSize = static_cast<int>(sRawResponse.size());

    while (iTotalSent < iResponseSize)
    {
        int iSent = send(iClientFd, sRawResponse.c_str() + iTotalSent, iResponseSize - iTotalSent, 0);

        if (iSent < 0)
        {
            rLogger.Log("Failed to send response to client.", ELogLevel::LOG_ERROR);
            break;
        }

        iTotalSent = iTotalSent + iSent;
    }

    rLogger.Log("Sent response (" + std::to_string(iTotalSent) + " bytes)", ELogLevel::INFO);
}

std::string CServer::ReadRequestSSL(SSL* ssl)
{
    const int BUFFER_SIZE = 4096;
    char buffer[BUFFER_SIZE];
    std::string request;

    while (true)
    {
        int iResult = SSL_read(ssl, buffer, BUFFER_SIZE);
        if (iResult <= 0)
        {
            rLogger.Log("SSL_read() failed.", ELogLevel::LOG_ERROR);
            return request;
        }

        request.append(buffer, iResult);
        const size_t headerEnd = request.find("\r\n\r\n");
        if (headerEnd == std::string::npos)
            continue;

        const size_t bodyStart = headerEnd + 4;
        if (request.size() >= bodyStart + ContentLength(request, headerEnd))
            break;
    }

    rLogger.Log("Raw HTTPS request received:\n" + request, ELogLevel::INFO);
    return request;
}

void CServer::SendResponseSSL(SSL* ssl, const HttpResponse& rResponse)
{
    std::string sRawResponse = rResponse.ToString();
    int iTotalSent = 0;
    int iResponseSize = static_cast<int>(sRawResponse.size());

    while (iTotalSent < iResponseSize) 
    {
        int iSent = SSL_write(ssl, sRawResponse.c_str() + iTotalSent, iResponseSize - iTotalSent);
        if (iSent <= 0) 
        {
            rLogger.Log("SSL_write() failed.", ELogLevel::LOG_ERROR);
            break;
        }
        iTotalSent += iSent;
    }
    rLogger.Log("Sent HTTPS response (" + std::to_string(iTotalSent) + " bytes)", ELogLevel::INFO);
}
