/********************************************************
 * Description : udp xactor
 * Author      : yanrk
 * Email       : yanrkchina@163.com
 * Version     : 2.0
 * History     :
 * Copyright(C): 2019-2020
 ********************************************************/

#ifdef _MSC_VER
    #include <ws2tcpip.h>
    #include <winsock2.h>
#else
    #include <errno.h>
    #include <netdb.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <signal.h>
    #include <arpa/inet.h>
    #include <sys/types.h>
    #include <sys/epoll.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
#endif // _MSC_VER

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <map>
#include <mutex>
#include <thread>
#include <vector>

#include "cauchy_fec.h"
#include "udp_xactor.h"

#ifdef _MSC_VER
    typedef HANDLE                  xactor_t;
    typedef SOCKET                  socket_t;
    typedef int                     sockaddr_len_t;
    typedef SOCKADDR                sockaddr_t;
    typedef SOCKADDR_IN             sockaddr_in_t;
    typedef IN_ADDR                 in_address_t;
#else
    typedef int                     xactor_t;
    typedef int                     socket_t;
    typedef socklen_t               sockaddr_len_t;
    typedef struct sockaddr         sockaddr_t;
    typedef struct sockaddr_in      sockaddr_in_t;
    typedef struct in_addr          in_address_t;
#endif // _MSC_VER

#ifdef _MSC_VER
    #define BAD_XACTOR              (nullptr)
    #define BAD_SOCKET              (INVALID_SOCKET)
    #define close_socket(sockfd)    ::closesocket(sockfd)
    #define net_error()             (::WSAGetLastError())
#else
    #define BAD_XACTOR              (-1)
    #define BAD_SOCKET              (-1)
    #define close_socket(sockfd)    ::close(sockfd)
    #define net_error()             (errno + 0)
#endif // _MSC_VER

#define RUN_LOG_ERR(fmt, ...) printf(fmt "\n", ##__VA_ARGS__)

IUdpConnection::~IUdpConnection()
{

}

class UdpConnection : public IUdpConnection
{
public:
    UdpConnection(socket_t sockfd, void * user_data = nullptr);
    virtual ~UdpConnection();

public:
    bool init(bool use_fec);
    void exit();

public:
    virtual void set_user_data(void * user_data) override;
    virtual void * get_user_data() override;

public:
    socket_t get_socket();

public:
    bool use_fec();

public:
    CauchyFecEncoder & get_fec_encoder();
    CauchyFecDecoder & get_fec_decoder();

private:
    socket_t                m_sockfd;
    void                  * m_user_data;

private:
    bool                    m_use_fec;
    CauchyFecEncoder        m_fec_encoder;
    CauchyFecDecoder        m_fec_decoder;
};

UdpConnection::UdpConnection(socket_t sockfd, void * user_data)
    : m_sockfd(sockfd)
    , m_user_data(user_data)
    , m_use_fec(false)
    , m_fec_encoder()
    , m_fec_decoder()
{

}

UdpConnection::~UdpConnection()
{
    exit();
}

bool UdpConnection::init(bool use_fec)
{
    m_use_fec = use_fec;
    if (use_fec)
    {
        return (m_fec_encoder.init(1200, 0.05, true) && m_fec_decoder.init(15));
    }
    return (true);
}

void UdpConnection::exit()
{
    m_sockfd = BAD_SOCKET;
    m_user_data = nullptr;
    m_fec_encoder.exit();
    m_fec_decoder.exit();
}

void UdpConnection::set_user_data(void * user_data)
{
    m_user_data = user_data;
}

void * UdpConnection::get_user_data()
{
    return (m_user_data);
}

socket_t UdpConnection::get_socket()
{
    return (m_sockfd);
}

bool UdpConnection::use_fec()
{
    return (m_use_fec);
}

CauchyFecEncoder & UdpConnection::get_fec_encoder()
{
    return (m_fec_encoder);
}

CauchyFecDecoder & UdpConnection::get_fec_decoder()
{
    return (m_fec_decoder);
}

#ifndef _MSC_VER
typedef void sig_func(int);

static sig_func * safe_signal(int signo, sig_func * func)
{
    struct sigaction new_act;
    new_act.sa_handler = func;
    sigemptyset(&new_act.sa_mask);
    new_act.sa_flags = 0;
    if (SIGALRM == signo)
    {
#ifdef SA_INTERRUPT
        new_act.sa_flags |= SA_INTERRUPT;
#endif
    }
    else
    {
#ifdef SA_RESTART
        new_act.sa_flags |= SA_RESTART;
#endif
    }

    struct sigaction old_act;
    if (sigaction(signo, &new_act, &old_act) < 0)
    {
        return (SIG_ERR);
    }
    else
    {
        return (old_act.sa_handler);
    }
}
#endif // _MSC_VER

bool init_network()
{
#ifdef _MSC_VER
    WSADATA wsa_data = { 0x0 };
    if (0 != WSAStartup(MAKEWORD(2, 2), &wsa_data))
#else
    if (SIG_ERR == safe_signal(SIGPIPE, SIG_IGN))
#endif // _MSC_VER
    {
        RUN_LOG_ERR("init network failed: %d", net_error());
        return (false);
    }
    return (true);
}

bool exit_network()
{
#ifdef _MSC_VER
    if (0 != WSACleanup())
#else
    if (SIG_ERR == safe_signal(SIGPIPE, SIG_DFL))
#endif // _MSC_VER
    {
        RUN_LOG_ERR("exit network failed: %d", net_error());
        return (false);
    }
    return (true);
}

static bool transform_address(const char * ip, unsigned short port, sockaddr_in_t & address)
{
    if (nullptr == ip)
    {
        RUN_LOG_ERR("ip is invalid");
        return (false);
    }
    memset(&address, 0x0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    return (::inet_pton(AF_INET, ip, &address.sin_addr) > 0);
}

static bool resolve_address(const sockaddr_in_t & address, std::string & ip, unsigned short & port)
{
    port = ntohs(address.sin_port);
    char buffer[16] = { 0x0 };
    if (nullptr == ::inet_ntop(AF_INET, const_cast<in_address_t *>(&address.sin_addr), buffer, sizeof(buffer)))
    {
        return (false);
    }
    ip = buffer;
    return (true);
}

static bool udp_open(socket_t & sockfd)
{
    sockfd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (BAD_SOCKET == sockfd)
    {
        RUN_LOG_ERR("socket failed: %d", net_error());
        return (false);
    }
    return (true);
}

static void udp_close(socket_t sockfd)
{
    if (BAD_SOCKET != sockfd)
    {
        close_socket(sockfd);
    }
}

static bool udp_reuse_addr(socket_t sockfd)
{
    const int reuse_addr = 1;
    if (::setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&reuse_addr), sizeof(reuse_addr)) < 0)
    {
        RUN_LOG_ERR("setsockopt(reuse-addr) failed: %d", net_error());
        return (false);
    }
    return (true);
}

static bool udp_reuse_port(socket_t sockfd)
{
#ifndef _MSC_VER
    const int reuse_port = 1;
    if (::setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<const char *>(&reuse_port), sizeof(reuse_port)) < 0)
    {
        RUN_LOG_ERR("setsockopt(reuse-port) failed: %d", net_error());
        return (false);
    }
#endif // _MSC_VER
    return (true);
}

static bool udp_bind(socket_t sockfd, const sockaddr_in_t & address)
{
    if (::bind(sockfd, reinterpret_cast<sockaddr_t *>(const_cast<sockaddr_in_t *>(&address)), sizeof(address)) < 0)
    {
        RUN_LOG_ERR("bind failed: %d", net_error());
        return (false);
    }
    return (true);
}

static bool udp_bind(socket_t & sockfd, const sockaddr_in_t & host_address, bool reuse_addr, bool reuse_port)
{
    if (!udp_open(sockfd))
    {
        return (false);
    }

    do
    {
        if (reuse_addr && !udp_reuse_addr(sockfd))
        {
            break;
        }

        if (reuse_port && !udp_reuse_port(sockfd))
        {
            break;
        }

        if (!udp_bind(sockfd, host_address))
        {
            break;
        }

        return (true);
    } while (false);

    udp_close(sockfd);
    sockfd = BAD_SOCKET;

    return (false);
}

static bool udp_bind(socket_t & sockfd, const char * host_ip, unsigned short host_port, bool reuse_addr, bool reuse_port)
{
    if (nullptr == host_ip || 0 == host_port)
    {
        return (udp_open(sockfd));
    }
    else
    {
        sockaddr_in_t host_address = { 0x0 };
        return (transform_address(host_ip, host_port, host_address) && udp_bind(sockfd, host_address, reuse_addr, reuse_port));
    }
}

static bool udp_connect(socket_t sockfd, const sockaddr_in_t & peer_address)
{
    if (::connect(sockfd, reinterpret_cast<sockaddr_t *>(const_cast<sockaddr_in_t *>(&peer_address)), sizeof(peer_address)) < 0)
    {
        RUN_LOG_ERR("connect failed: %d", net_error());
        return (false);
    }
    return (true);
}

static bool udp_connect(socket_t & sockfd, const sockaddr_in_t & peer_address, const char * host_ip, unsigned short host_port, bool reuse_addr, bool reuse_port)
{
    if (!udp_bind(sockfd, host_ip, host_port, reuse_addr, reuse_port))
    {
        return (false);
    }

    if (udp_connect(sockfd, peer_address))
    {
        return (true);
    }

    udp_close(sockfd);
    sockfd = BAD_SOCKET;

    return (false);
}

static bool udp_connect(socket_t & sockfd, const char * peer_ip, unsigned short peer_port, const char * host_ip, unsigned short host_port, bool reuse_addr, bool reuse_port)
{
    if (nullptr == peer_ip || 0 == peer_port)
    {
        return (false);
    }
    else
    {
        sockaddr_in_t peer_address = { 0x0 };
        return (transform_address(peer_ip, peer_port, peer_address) && udp_connect(sockfd, peer_address, host_ip, host_port, reuse_addr, reuse_port));
    }
}

static bool udp_send(socket_t sockfd, const sockaddr_in_t & peer_address, const char * data, std::size_t data_size)
{
    if (nullptr == data && 0 != data_size)
    {
        RUN_LOG_ERR("sendto failed: invalid data");
        return (false);
    }

    sockaddr_len_t addr_len = static_cast<sockaddr_len_t>(sizeof(peer_address));
    int send_len = ::sendto(sockfd, data, static_cast<int>(data_size), 0, reinterpret_cast<const sockaddr_t *>(&peer_address), addr_len);
    if (send_len < 0 || send_len != static_cast<int>(data_size))
    {
        RUN_LOG_ERR("sendto failed: %d", net_error());
        return (false);
    }

    return (true);
}

static bool udp_send(socket_t sockfd, const char * data, std::size_t data_size)
{
    if (nullptr == data && 0 != data_size)
    {
        RUN_LOG_ERR("send failed: invalid data");
        return (false);
    }

    int send_len = ::send(sockfd, data, static_cast<int>(data_size), 0);
    if (send_len < 0 || send_len != static_cast<int>(data_size))
    {
        RUN_LOG_ERR("send failed: %d", net_error());
        return (false);
    }

    return (true);
}

static bool udp_recv(socket_t sockfd, sockaddr_in_t & peer_address, char * buff, std::size_t buff_size, std::size_t & recv_size)
{
    if (nullptr == buff && 0 != buff_size)
    {
        RUN_LOG_ERR("recvfrom failed: invalid buffer");
        return (false);
    }

    sockaddr_len_t addr_len = static_cast<sockaddr_len_t>(sizeof(peer_address));
    int recv_len = ::recvfrom(sockfd, buff, static_cast<int>(buff_size), 0, reinterpret_cast<sockaddr_t *>(&peer_address), &addr_len);
    if (recv_len < 0)
    {
        RUN_LOG_ERR("recvfrom failed: %d", net_error());
        return (false);
    }
    recv_size = static_cast<std::size_t>(recv_len);

    return (true);
}

static bool udp_recv(socket_t sockfd, char * buff, std::size_t buff_size, std::size_t & recv_size)
{
    if (nullptr == buff && 0 != buff_size)
    {
        RUN_LOG_ERR("recv failed: invalid buffer");
        return (false);
    }

    int recv_len = ::recv(sockfd, buff, static_cast<int>(buff_size), 0);
    if (recv_len < 0)
    {
        RUN_LOG_ERR("recv failed: %d", net_error());
        return (false);
    }
    recv_size = static_cast<std::size_t>(recv_len);

    return (true);
}

static bool udp_set_block_switch(socket_t sockfd, bool blocking)
{
#ifdef _MSC_VER
    u_long non_blocking_mode = (blocking ? 0 : 1);
    int ret = ::ioctlsocket(sockfd, FIONBIO, &non_blocking_mode);
    if (ret < 0)
    {
        RUN_LOG_ERR("ioctlsocket(%s) failed: %d", (blocking ? "blocking" : "non-blocking"), net_error());
        return (false);
    }
    return (true);
#else
    int flags = ::fcntl(sockfd, F_GETFL, 0);
    if (flags < 0)
    {
        RUN_LOG_ERR("fcntl(get-%s-flags) failed: %d", (blocking ? "blocking" : "non-blocking"), net_error());
        return (false);
    }
    if (blocking)
    {
        flags &= ~O_NONBLOCK;
    }
    else
    {
        flags |= O_NONBLOCK;
    }
    int ret = ::fcntl(sockfd, F_SETFL, flags);
    if (ret < 0)
    {
        RUN_LOG_ERR("fcntl(set-%s-flags) failed: %d", (blocking ? "blocking" : "non-blocking"), net_error());
        return (false);
    }
    return (true);
#endif // _MSC_VER
}

static bool udp_set_send_timeout(socket_t sockfd, std::size_t send_timeout_ms)
{
#ifdef _MSC_VER
    int timeout = static_cast<int>(send_timeout_ms);
#else
    struct timeval timeout = { static_cast<time_t>(send_timeout_ms) / 1000, static_cast<suseconds_t>(send_timeout_ms % 1000 * 1000) };
#endif // _MSC_VER
    int ret = ::setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char *>(&timeout), sizeof(timeout));
    if (ret < 0)
    {
        RUN_LOG_ERR("setsockopt(send-timeout) failed: %d", net_error());
        return (false);
    }
    return (true);
}

static bool udp_set_recv_timeout(socket_t sockfd, std::size_t recv_timeout_ms)
{
#ifdef _MSC_VER
    int timeout = static_cast<int>(recv_timeout_ms);
#else
    struct timeval timeout = { static_cast<time_t>(recv_timeout_ms / 1000), static_cast<suseconds_t>(recv_timeout_ms % 1000 * 1000) };
#endif // _MSC_VER
    int ret = ::setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char *>(&timeout), sizeof(timeout));
    if (ret < 0)
    {
        RUN_LOG_ERR("setsockopt(recv-timeout) failed: %d", net_error());
        return (false);
    }
    return (true);
}

static bool udp_get_host_address(socket_t sockfd, sockaddr_in_t & address)
{
    sockaddr_len_t addr_len = static_cast<sockaddr_len_t>(sizeof(address));
    if (0 != ::getsockname(sockfd, reinterpret_cast<sockaddr_t *>(&address), &addr_len))
    {
        RUN_LOG_ERR("getsockname failed: %d", net_error());
        return (false);
    }
    return (true);
}

static bool udp_get_peer_address(socket_t sockfd, sockaddr_in_t & address)
{
    sockaddr_len_t addr_len = static_cast<sockaddr_len_t>(sizeof(address));
    if (0 != ::getpeername(sockfd, reinterpret_cast<sockaddr_t *>(&address), &addr_len))
    {
        RUN_LOG_ERR("getpeername failed: %d", net_error());
        return (false);
    }
    return (true);
}

static bool operator < (const sockaddr_in_t & lhs, const sockaddr_in_t & rhs)
{
    return (memcmp(&lhs, &rhs, sizeof(sockaddr_in_t)) < 0);
}

static bool find_socket(std::mutex & connection_mutex, const std::map<sockaddr_in_t, UdpConnection *> & connection_map, const sockaddr_in_t & address, socket_t & sockfd)
{
    std::lock_guard<std::mutex> locker(connection_mutex);
    std::map<sockaddr_in_t, UdpConnection *>::const_iterator iter = connection_map.find(address);
    if (connection_map.end() != iter)
    {
        sockfd = iter->second->get_socket();
        return (true);
    }
    else
    {
        sockfd = BAD_SOCKET;
        return (false);
    }
}

static bool insert_connection(std::mutex & connection_mutex, std::map<sockaddr_in_t, UdpConnection *> & connection_map, const sockaddr_in_t & address, UdpConnection * connection)
{
    std::lock_guard<std::mutex> locker(connection_mutex);
    if (connection_map.end() == connection_map.find(address))
    {
        connection_map[address] = connection;
        return (true);
    }
    return (false);
}

static bool remove_connection(std::mutex & connection_mutex, std::map<sockaddr_in_t, UdpConnection *> & connection_map, IUdpSink * udp_sink, UdpConnection * connection)
{
    std::lock_guard<std::mutex> locker(connection_mutex);
    for (std::map<sockaddr_in_t, UdpConnection *>::iterator iter = connection_map.begin(); connection_map.end() != iter; ++iter)
    {
        if (iter->second->get_socket() == connection->get_socket())
        {
            udp_sink->on_close(connection);
            udp_close(connection->get_socket());
            connection_map.erase(iter);
            delete connection;
            return (true);
        }
    }
    return (false);
}

static void clear_connections(std::mutex & connection_mutex, std::map<sockaddr_in_t, UdpConnection *> & connection_map, IUdpSink * udp_sink)
{
    std::lock_guard<std::mutex> locker(connection_mutex);
    for (std::map<sockaddr_in_t, UdpConnection *>::iterator iter = connection_map.begin(); connection_map.end() != iter; ++iter)
    {
        UdpConnection * connection = iter->second;
        udp_sink->on_close(connection);
        udp_close(connection->get_socket());
        delete connection;
    }
    connection_map.clear();
}

static bool handle_recv_data(UdpConnection * connection, const void * data, std::size_t size, IUdpSink * udp_sink)
{
    if (nullptr == connection || nullptr == data || nullptr == udp_sink)
    {
        return (false);
    }

    socket_t sockfd = connection->get_socket();
    if (BAD_SOCKET == sockfd)
    {
        return (false);
    }

    if (connection->use_fec())
    {
        std::list<std::vector<uint8_t>> dst_list;
        CauchyFecDecoder & fec_decoder = connection->get_fec_decoder();
        if (!fec_decoder.decode(reinterpret_cast<const uint8_t *>(data), static_cast<uint32_t>(size), dst_list))
        {
            return (false);
        }

        for (std::list<std::vector<uint8_t>>::const_iterator iter = dst_list.begin(); dst_list.end() != iter; ++iter)
        {
            const std::vector<uint8_t> & piece = *iter;
            udp_sink->on_recv(connection, reinterpret_cast<const char *>(&piece[0]), piece.size());
        }
    }
    else
    {
        udp_sink->on_recv(connection, data, size);
    }
    return (true);
}

static bool handle_send_data(UdpConnection * connection, const void * data, std::size_t size)
{
    if (nullptr == connection || nullptr == data)
    {
        return (false);
    }

    socket_t sockfd = connection->get_socket();
    if (BAD_SOCKET == sockfd)
    {
        return (false);
    }

    if (connection->use_fec())
    {
        std::list<std::vector<uint8_t>> dst_list;
        CauchyFecEncoder & fec_encoder = connection->get_fec_encoder();
        if (!fec_encoder.encode(reinterpret_cast<const uint8_t *>(data), static_cast<uint32_t>(size), dst_list))
        {
            return (false);
        }

        bool ret = !dst_list.empty();
        for (std::list<std::vector<uint8_t>>::const_iterator iter = dst_list.begin(); dst_list.end() != iter; ++iter)
        {
            const std::vector<uint8_t> & piece = *iter;
            if (!udp_send(sockfd, reinterpret_cast<const char *>(&piece[0]), piece.size()))
            {
                ret = false;
            }
        }
        return (ret);
    }
    else
    {
        return (udp_send(sockfd, reinterpret_cast<const char *>(data), size));
    }
}

#ifdef _MSC_VER

struct iocp_event_t
{
    OVERLAPPED      overlapped;
    UdpConnection * connection;
    WSABUF          data;
    char            buffer[1600];
    std::size_t     buffer_size;
};

static bool create_event(UdpConnection * connection, iocp_event_t *& event)
{
    if (nullptr == connection || BAD_SOCKET == connection->get_socket())
    {
        return (false);
    }
    event = new iocp_event_t;
    if (nullptr == event)
    {
        RUN_LOG_ERR("create event failed");
        return (false);
    }
    memset(&event->overlapped, 0x0, sizeof(event->overlapped));
    memset(event->buffer, 0x0, sizeof(event->buffer));
    event->buffer_size = sizeof(event->buffer) / sizeof(event->buffer[0]);
    event->data.buf = event->buffer;
    event->data.len = static_cast<ULONG>(event->buffer_size);
    event->connection = connection;
    return (true);
}

static void destroy_event(iocp_event_t *& event)
{
    if (nullptr != event)
    {
        delete event;
        event = nullptr;
    }
}

static bool create_iocp(HANDLE & iocp_handle)
{
    iocp_handle = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
    if (nullptr == iocp_handle)
    {
        RUN_LOG_ERR("create iocp failed: %d", net_error());
        return (false);
    }
    return (true);
}

static void destroy_iocp(HANDLE & iocp_handle)
{
    if (nullptr != iocp_handle)
    {
        ::CloseHandle(iocp_handle);
        iocp_handle = nullptr;
    }
}

static bool append_to_iocp(HANDLE iocp_handle, iocp_event_t * event)
{
    if (nullptr == iocp_handle || nullptr == event || nullptr == event->connection || BAD_SOCKET == event->connection->get_socket())
    {
        return (false);
    }
    if (nullptr == ::CreateIoCompletionPort(reinterpret_cast<HANDLE>(event->connection->get_socket()), iocp_handle, reinterpret_cast<ULONG_PTR>(event), 0))
    {
        RUN_LOG_ERR("append to iocp failed: %d", net_error());
        return (false);
    }
    return (true);
}

static bool post_recv(iocp_event_t * event)
{
    if (nullptr == event || nullptr == event->connection || BAD_SOCKET == event->connection->get_socket())
    {
        return (false);
    }
    WSABUF buffer_array[1] = { event->data };
    DWORD recv_len = 0;
    DWORD recv_flg = 0;
    if (SOCKET_ERROR == ::WSARecv(event->connection->get_socket(), buffer_array, 1, &recv_len, &recv_flg, &event->overlapped, nullptr))
    {
        if (WSA_IO_PENDING != net_error())
        {
            RUN_LOG_ERR("post recv failed: %d", net_error());
            return (false);
        }
    }
    return (true);
}

static void post_exit(HANDLE iocp_handle)
{
    if (nullptr != iocp_handle)
    {
        if (!::PostQueuedCompletionStatus(iocp_handle, 0, 0, nullptr))
        {
            RUN_LOG_ERR("post exit failed: %d", net_error());
        }
    }
}

static bool create_xactor(xactor_t & xactor)
{
    return (create_iocp(xactor));
}

static void destroy_xactor(xactor_t & xactor, std::size_t handle_thread_count)
{
    for (std::size_t index = 0; index < handle_thread_count; ++index)
    {
        post_exit(xactor);
    }
    std::this_thread::sleep_for(std::chrono::seconds(3));
    destroy_iocp(xactor);
}

static bool append_to_xactor(xactor_t xactor, UdpConnection * connection)
{
    if (nullptr == connection || BAD_SOCKET == connection->get_socket())
    {
        return (false);
    }

    iocp_event_t * event = nullptr;
    if (!create_event(connection, event))
    {
        return (false);
    }

    do
    {
        if (!append_to_iocp(xactor, event))
        {
            break;
        }

        if (!post_recv(event))
        {
            break;
        }

        return (true);
    } while (false);

    destroy_event(event);

    return (false);
}

static void handle_recv(volatile bool & running, xactor_t xactor, std::mutex & connection_mutex, std::map<sockaddr_in_t, UdpConnection *> & connection_map, IUdpSink * udp_sink)
{
    while (running)
    {
        bool good = false;
        DWORD data_len = 0;
        iocp_event_t * event = nullptr;
        OVERLAPPED * overlapped = nullptr;

        if (::GetQueuedCompletionStatus(xactor, &data_len, reinterpret_cast<PULONG_PTR>(&event), &overlapped, INFINITE))
        {
            good = true;
        }

        if (nullptr == event || nullptr == overlapped)
        {
            continue;
        }

        if (good)
        {
            if (nullptr != event->connection && 0 != data_len)
            {
                handle_recv_data(event->connection, event->buffer, data_len, udp_sink);
            }
            good = post_recv(event);
        }

        if (!good)
        {
            if (ERROR_SUCCESS != net_error() && ERROR_NETNAME_DELETED != net_error() && ERROR_CONNECTION_ABORTED != net_error())
            {
                RUN_LOG_ERR("iocp error: %d", net_error());
            }
            remove_connection(connection_mutex, connection_map, udp_sink, event->connection);
            destroy_event(event);
        }
    }
}

#else

static bool create_epoll(int & epoll_fd)
{
    epoll_fd = ::epoll_create(99999);
    if (-1 == epoll_fd)
    {
        RUN_LOG_ERR("create epoll failed: %d", net_error());
        return (false);
    }
    return (true);
}

static void destroy_epoll(int & epoll_fd)
{
    if (-1 != epoll_fd)
    {
        ::close(epoll_fd);
        epoll_fd = -1;
    }
}

static bool append_to_epoll(int epoll_fd, UdpConnection * connection)
{
    if (-1 == epoll_fd || nullptr == connection || BAD_SOCKET == connection->get_socket())
    {
        return (false);
    }
    struct epoll_event event = { 0x0 };
    event.data.ptr = connection;
    event.events = EPOLLIN | EPOLLET;
    if (-1 == ::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, connection->get_socket(), &event))
    {
        RUN_LOG_ERR("append to epoll failed: %d", net_error());
        return (false);
    }
    return (true);
}

static bool delete_from_epoll(int epoll_fd, UdpConnection * connection)
{
    if (-1 == epoll_fd || nullptr == connection || BAD_SOCKET == connection->get_socket())
    {
        return (false);
    }
    struct epoll_event event = { 0x0 };
    if (-1 == ::epoll_ctl(epoll_fd, EPOLL_CTL_DEL, connection->get_socket(), &event))
    {
        RUN_LOG_ERR("delete from epoll failed: %d", net_error());
        return (false);
    }
    return (true);
}

static bool post_recv(int epoll_fd, UdpConnection * connection)
{
    if (-1 == epoll_fd || nullptr == connection || BAD_SOCKET == connection->get_socket())
    {
        return (false);
    }
    struct epoll_event event = { 0x0 };
    event.data.ptr = connection;
    event.events = EPOLLIN | EPOLLET;
    if (-1 == ::epoll_ctl(epoll_fd, EPOLL_CTL_MOD, connection->get_socket(), &event))
    {
        RUN_LOG_ERR("post recv failed: %d", net_error());
        return (false);
    }
    return (true);
}

static bool create_xactor(xactor_t & xactor)
{
    return (create_epoll(xactor));
}

static void destroy_xactor(xactor_t & xactor, std::size_t handle_thread_count)
{
    destroy_epoll(xactor);
}

static bool append_to_xactor(xactor_t xactor, UdpConnection * connection)
{
    return (append_to_epoll(xactor, connection));
}

static void handle_recv(volatile bool & running, xactor_t xactor, std::mutex & connection_mutex, std::map<sockaddr_in_t, UdpConnection *> & connection_map, IUdpSink * udp_sink)
{
    struct epoll_event event_array[256];
    const std::size_t max_event_count = sizeof(event_array) / sizeof(event_array[0]);
    const std::size_t wait_timeout = 1000;

    while (running)
    {
        int event_count = ::epoll_wait(xactor, event_array, max_event_count, wait_timeout);
        if (-1 == event_count)
        {
            if (!running)
            {
                continue;
            }
            else if (EINTR == net_error() || EAGAIN == net_error() || EWOULDBLOCK == net_error())
            {
                continue;
            }
            else
            {
                RUN_LOG_ERR("epoll wait failed: %d", net_error());
                break;
            }
        }
        else if (0 == event_count)
        {
            continue;
        }

        for (int index = 0; index < event_count; ++index)
        {
            const struct epoll_event & event = event_array[index];
            uint32_t events = event.events;
            UdpConnection * connection = reinterpret_cast<UdpConnection *>(event.data.ptr);
            bool good = (0 == (events & EPOLLERR));
            if (good && (0 != (events & EPOLLIN)))
            {
                char buffer[1600] = { 0x0 };
                std::size_t recv_size = 0;
                if (udp_recv(connection->get_socket(), buffer, sizeof(buffer), recv_size) && 0 != recv_size)
                {
                    handle_recv_data(connection, buffer, recv_size, udp_sink);
                }
                if (!post_recv(xactor, connection))
                {
                    good = false;
                }
            }
            if (!good)
            {
                delete_from_epoll(xactor, connection);
                remove_connection(connection_mutex, connection_map, udp_sink, connection);
            }
        }
    }
}

#endif // _MSC_VER

IUdpSink::~IUdpSink()
{

}

IUdpXactor::~IUdpXactor()
{

}

class UdpXactor : public IUdpXactor
{
public:
    UdpXactor();
    virtual ~UdpXactor() override;

public:
    virtual bool init(IUdpSink * udp_sink, bool use_fec, std::size_t thread_count, const char * host_ip, unsigned short host_port, bool reuse_addr, bool reuse_port) override;
    virtual void exit() override;

public:
    virtual bool connect(const char * peer_ip, unsigned short peer_port, void * user_data, const char * host_ip, unsigned short host_port, bool reuse_addr, bool reuse_port) override;
    virtual bool send(IUdpConnection * connection, const void * data, std::size_t size) override;
    virtual bool close(IUdpConnection * connection) override;

private:
    void accept();

private:
    volatile bool                                       m_running;
    bool                                                m_use_fec;
    xactor_t                                            m_xactor;
    IUdpSink                                          * m_udp_sink;
    sockaddr_in_t                                       m_address;
    socket_t                                            m_listener;
    std::thread                                         m_listen_thread;
    std::vector<std::thread>                            m_recv_threads;

private:
    std::map<sockaddr_in_t, UdpConnection *>            m_connection_map;
    std::mutex                                          m_connection_mutex;
};

UdpXactor::UdpXactor()
    : m_running(false)
    , m_use_fec(false)
    , m_xactor(BAD_XACTOR)
    , m_udp_sink(nullptr)
    , m_address()
    , m_listener(BAD_SOCKET)
    , m_listen_thread()
    , m_recv_threads()
    , m_connection_map()
    , m_connection_mutex()
{
    memset(&m_address, 0x0, sizeof(m_address));
}

UdpXactor::~UdpXactor()
{
    exit();
}

bool UdpXactor::init(IUdpSink * udp_sink, bool use_fec, std::size_t thread_count, const char * host_ip, unsigned short host_port, bool reuse_addr, bool reuse_port)
{
    exit();

    m_running = true;

    m_use_fec = use_fec;

    if (nullptr == udp_sink)
    {
        RUN_LOG_ERR("udp xactor init failure while udp sink is invalid");
        return (false);
    }

    m_udp_sink = udp_sink;

    if (!create_xactor(m_xactor))
    {
        RUN_LOG_ERR("udp xactor init failure while create xactor failed");
        return (false);
    }

    if (nullptr != host_ip && 0 != host_port)
    {
        if (!udp_bind(m_listener, host_ip, host_port, reuse_addr, reuse_port))
        {
            RUN_LOG_ERR("udp xactor init failure while udp bind failed");
            return (false);
        }

        if (!udp_get_host_address(m_listener, m_address))
        {
            RUN_LOG_ERR("udp xactor init failure while udp get host address failed");
            return (false);
        }

        m_listen_thread = std::thread(std::bind(&UdpXactor::accept, this));
    }

#ifdef _MSC_VER
    if (thread_count < 1)
    {
        thread_count = 1;
    }
    else if (thread_count > 5)
    {
        thread_count = 5;
    }
#else
    thread_count = 1;
#endif // _MSC_VER

    m_recv_threads.reserve(thread_count);
    for (std::size_t thread_index = 0; thread_index < thread_count; ++thread_index)
    {
        m_recv_threads.emplace_back(std::thread(std::bind(&handle_recv, std::ref(m_running), std::ref(m_xactor), std::ref(m_connection_mutex), std::ref(m_connection_map), m_udp_sink)));
    }

    return (true);
}

void UdpXactor::exit()
{
    if (m_running)
    {
        m_running = false;

        if (BAD_SOCKET != m_listener)
        {
            std::string host_ip;
            unsigned short host_port = 0;
            resolve_address(m_address, host_ip, host_port);
            socket_t sockfd = BAD_SOCKET;
            udp_connect(sockfd, "0.0.0.0" == host_ip ? "127.0.0.1" : host_ip.c_str(), host_port, nullptr, 0, false, false);
            udp_send(sockfd, nullptr, 0);
            udp_close(sockfd);
            sockfd = BAD_SOCKET;

            if (m_listen_thread.joinable())
            {
                m_listen_thread.join();
            }

            udp_close(m_listener);
            m_listener = BAD_SOCKET;
        }

        destroy_xactor(m_xactor, m_recv_threads.size());

        for (std::vector<std::thread>::iterator iter = m_recv_threads.begin(); m_recv_threads.end() != iter; ++iter)
        {
            iter->join();
        }
        m_recv_threads.clear();

        clear_connections(m_connection_mutex, m_connection_map, m_udp_sink);

        m_use_fec = false;
        m_udp_sink = nullptr;
    }
}

void UdpXactor::accept()
{
    while (m_running)
    {
        sockaddr_in_t recv_address = { 0x0 };
        std::size_t recv_size = 0;
        if (!udp_recv(m_listener, recv_address, nullptr, 0, recv_size))
        {
            continue;
        }

        if (!m_running)
        {
            break;
        }

        socket_t connector = BAD_SOCKET;
        if (find_socket(m_connection_mutex, m_connection_map, recv_address, connector))
        {
            udp_send(connector, nullptr, 0);
            continue;
        }

#ifdef _MSC_VER
        if (!udp_open(connector))
#else
        if (!udp_bind(connector, m_address, true, true))
#endif // _MSC_VER
        {
            continue;
        }

        UdpConnection * connection = nullptr;

        do
        {
            if (!udp_connect(connector, recv_address))
            {
                break;
            }

            if (!udp_send(connector, nullptr, 0))
            {
                break;
            }

            if (!udp_set_recv_timeout(connector, 0))
            {
                break;
            }
            /*
            if (!udp_set_block_switch(connector, false))
            {
                break;
            }
            */

            connection = new UdpConnection(connector);
            if (nullptr == connection)
            {
                break;
            }

            if (!connection->init(m_use_fec))
            {
                break;
            }

            if (!insert_connection(m_connection_mutex, m_connection_map, recv_address, connection))
            {
                break;
            }

            m_udp_sink->on_accept(connection);

            if (!append_to_xactor(m_xactor, connection))
            {
                remove_connection(m_connection_mutex, m_connection_map, m_udp_sink, connection);
            }

            connection = nullptr;
            connector = BAD_SOCKET;
        } while (false);

        if (nullptr != connection)
        {
            delete connection;
            connection = nullptr;
        }

        udp_close(connector);
        connector = BAD_SOCKET;
    }
}

bool UdpXactor::connect(const char * peer_ip, unsigned short peer_port, void * user_data, const char * host_ip, unsigned short host_port, bool reuse_addr, bool reuse_port)
{
    if (!m_running || nullptr == m_udp_sink)
    {
        return (false);
    }

    sockaddr_in_t peer_address = { 0x0 };
    if (!transform_address(peer_ip, peer_port, peer_address))
    {
        return (false);
    }

    socket_t connector = BAD_SOCKET;
    if (!udp_bind(connector, host_ip, host_port, reuse_addr, reuse_port))
    {
        return (false);
    }

    UdpConnection * connection = nullptr;

    do
    {
        if (!udp_set_block_switch(connector, true))
        {
            break;
        }

        if (!udp_set_recv_timeout(connector, 1000))
        {
            break;
        }

        sockaddr_in_t recv_address = { 0x0 };

        for (std::size_t index = 0; index < 10; ++index)
        {
            std::size_t recv_size = 0;
            if (udp_send(connector, peer_address, nullptr, 0) && udp_recv(connector, recv_address, nullptr, 0, recv_size) && 0 == memcmp(&peer_address.sin_addr, &recv_address.sin_addr, sizeof(in_address_t)))
            {
                break;
            }
        }

        if (0 != memcmp(&peer_address.sin_addr, &recv_address.sin_addr, sizeof(in_address_t)))
        {
            break;
        }

        if (!udp_connect(connector, recv_address))
        {
            break;
        }

        if (!udp_set_recv_timeout(connector, 0))
        {
            break;
        }
        /*
        if (!udp_set_block_switch(connector, false))
        {
            break;
        }
        */
        sockaddr_in_t host_address = { 0x0 };
        if (!udp_get_host_address(connector, host_address))
        {
            break;
        }

        connection = new UdpConnection(connector, user_data);
        if (nullptr == connection)
        {
            break;
        }

        if (!connection->init(m_use_fec))
        {
            break;
        }

        if (!insert_connection(m_connection_mutex, m_connection_map, host_address, connection))
        {
            break;
        }

        m_udp_sink->on_connect(connection, user_data);

        if (!append_to_xactor(m_xactor, connection))
        {
            remove_connection(m_connection_mutex, m_connection_map, m_udp_sink, connection);
            return (false);
        }

        return (true);
    } while (false);

    if (nullptr != connection)
    {
        delete connection;
        connection = nullptr;
    }

    udp_close(connector);
    connector = BAD_SOCKET;

    return (false);
}

bool UdpXactor::send(IUdpConnection * connection, const void * data, std::size_t size)
{
    return (handle_send_data(reinterpret_cast<UdpConnection *>(connection), data, size));
}

bool UdpXactor::close(IUdpConnection * connection)
{
    return (nullptr != connection && remove_connection(m_connection_mutex, m_connection_map, m_udp_sink, reinterpret_cast<UdpConnection *>(connection)));
}

IUdpXactor * create_udp_xactor()
{
    return (new UdpXactor);
}

void destroy_udp_xactor(IUdpXactor * udp_xactor)
{
    delete udp_xactor;
}
