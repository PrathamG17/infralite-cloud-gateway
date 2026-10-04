#ifndef SERVER_HPP
#define SERVER_HPP

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include <atomic>
#include <cerrno>
#include <string>

#include "logger.hpp"
#include "router.hpp"
#include "request.hpp"
#include "response.hpp"
#include "TLSContext.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif
#include <openssl/ssl.h>

#include "db/access_log_repository.hpp"

class Router;

namespace SocketPlatform
{
#ifdef _WIN32
    using Handle = SOCKET;
    using Length = int;
    constexpr Handle Invalid = INVALID_SOCKET;

    /** Initializes the Winsock runtime for the current process.
     * @return Zero on success, otherwise the Winsock error code.
     */
    inline int Startup()
    {
        WSADATA data;
        return WSAStartup(MAKEWORD(2, 2), &data);
    }
    /** Releases the Winsock runtime reference acquired by Startup.
     * @return No value.
     */
    inline void Cleanup() { WSACleanup(); }
    /** Returns the most recent platform socket error.
     * @return The platform-specific socket error code.
     */
    inline int LastError() { return WSAGetLastError(); }
    /** Closes a socket handle.
     * @param socket Handle to close.
     * @return Zero on success, otherwise a nonzero error result.
     */
    inline int Close(Handle socket) { return closesocket(socket); }
    /** Shuts down both directions of a socket before closing it.
     * @param socket Handle to shut down.
     * @return Zero on success, otherwise a nonzero error result.
     */
    inline int Shutdown(Handle socket) { return shutdown(socket, SD_BOTH); }
    /** Enables address reuse on a socket.
     * @param socket Handle to configure.
     * @param value Nonzero to enable address reuse.
     * @return Zero on success, otherwise a nonzero error result.
     */
    inline int SetReuseAddress(Handle socket, int value)
    {
        return setsockopt(socket, SOL_SOCKET, SO_REUSEADDR,
            reinterpret_cast<const char*>(&value), sizeof(value));
    }
    /** Sets the socket receive timeout.
     * @param socket Handle to configure.
     * @param milliseconds Timeout duration in milliseconds.
     * @return Zero on success, otherwise a nonzero error result.
     */
    inline int SetReceiveTimeout(Handle socket, unsigned int milliseconds)
    {
        DWORD timeout = milliseconds;
        return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    }
#else
    using Handle = int;
    using Length = socklen_t;
    constexpr Handle Invalid = -1;

    /** Provides a no-op startup hook for POSIX socket runtimes.
     * @return Zero, indicating success.
     */
    inline int Startup() { return 0; }
    /** Provides a no-op cleanup hook for POSIX socket runtimes.
     * @return No value.
     */
    inline void Cleanup() {}
    /** Returns the current thread's errno value.
     * @return The most recent POSIX socket error code.
     */
    inline int LastError() { return errno; }
    /** Closes a POSIX socket descriptor.
     * @param socket Descriptor to close.
     * @return Zero on success, otherwise -1.
     */
    inline int Close(Handle socket) { return close(socket); }
    /** Shuts down both directions of a socket before closing it.
     * @param socket Descriptor to shut down.
     * @return Zero on success, otherwise -1.
     */
    inline int Shutdown(Handle socket) { return shutdown(socket, SHUT_RDWR); }
    /** Enables address reuse on a socket.
     * @param socket Descriptor to configure.
     * @param value Nonzero to enable address reuse.
     * @return Zero on success, otherwise -1.
     */
    inline int SetReuseAddress(Handle socket, int value)
    {
        return setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));
    }
    /** Sets the socket receive timeout.
     * @param socket Descriptor to configure.
     * @param milliseconds Timeout duration in milliseconds.
     * @return Zero on success, otherwise -1.
     */
    inline int SetReceiveTimeout(Handle socket, unsigned int milliseconds)
    {
        timeval timeout{};
        timeout.tv_sec = milliseconds / 1000;
        timeout.tv_usec = (milliseconds % 1000) * 1000;
        return setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    }
#endif
}

/** Accepts HTTP(S) connections and dispatches requests through a Router.
 * Socket ownership remains with the server/client handling paths; referenced
 * router, logger, repositories, and TLS context must outlive the server.
 */
class CServer
{
private:
    int iPort;
    std::atomic<SocketPlatform::Handle> iServerFd;
    Router& rRouter;
    std::atomic<bool> bIsRunning;
    bool bSocketInitialized;
    Logger& rLogger;
    AccessLogRepository* m_pLogRepo;
    TLSContext* m_pTLS;

public:
    /** Constructs a plain HTTP server.
     * @param iPort TCP port to bind.
     * @param rRouter Router used to dispatch parsed requests.
     * @param rLogger Logger used for server diagnostics.
     * @param logRepo Optional repository receiving access records.
     * @return No value.
     */
    CServer(int iPort, Router& rRouter, Logger& rLogger, AccessLogRepository* logRepo);

    /** Constructs a server that uses TLS when a valid context is supplied.
     * @param iPort TCP port to bind.
     * @param rRouter Router used to dispatch parsed requests.
     * @param rLogger Logger used for server diagnostics.
     * @param logRepo Optional repository receiving access records.
     * @param pTLS Optional initialized TLS context; null selects HTTP.
     * @return No value.
     */
    CServer(int iPort, Router& rRouter, Logger& rLogger, AccessLogRepository* logRepo, TLSContext* pTLS);

    /** Closes remaining server resources and releases platform socket state. */
    ~CServer();

    /** Initializes the listener and serves clients until Stop is called.
     * @return No value.
     */
    void Run();

    /** Requests listener shutdown and unblocks a pending accept.
     * @return No value.
     */
    void Stop();

private:
    /** Creates, configures, binds, and listens on the server socket.
     * @return No value; throws std::runtime_error when setup fails.
     */
    void InitSocket();

    /** Waits for and returns one client socket.
     * @return Accepted handle, or SocketPlatform::Invalid on failure.
     */
    SocketPlatform::Handle AcceptClient() const;

    /** Reads, dispatches, logs, and responds to one client request.
     * @param iClientFd Connected client socket handle.
     * @return No value.
     */
    void HandleClient(SocketPlatform::Handle iClientFd);

    /** Reads one HTTP request from a plain socket.
     * @param iClientFd Connected client socket handle.
     * @return Raw request bytes, or an empty string on receive failure.
     */
    std::string ReadRequest(SocketPlatform::Handle iClientFd);

    /** Reads one HTTP request over an established TLS session.
     * @param ssl Established OpenSSL session.
     * @return Raw request bytes, or an empty string on receive failure.
     */
    std::string ReadRequestSSL(SSL* ssl);

    /** Sends an HTTP response over a plain socket.
     * @param iClientFd Connected client socket handle.
     * @param rResponse Response to serialize and send.
     * @return No value.
     */
    void SendResponse(SocketPlatform::Handle iClientFd, const HttpResponse& rResponse);

    /** Sends an HTTP response over an established TLS session.
     * @param ssl Established OpenSSL session.
     * @param rResponse Response to serialize and send.
     * @return No value.
     */
    void SendResponseSSL(SSL* ssl, const HttpResponse& rResponse);
};

#endif
