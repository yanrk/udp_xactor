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
#include <list>
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

static bool operator < (const sockaddr_in_t & lhs, const sockaddr_in_t & rhs)
{
    return memcmp(&lhs, &rhs, sizeof(sockaddr_in_t)) < 0;
}

static bool operator == (const sockaddr_in_t & lhs, const sockaddr_in_t & rhs)
{
    return 0 == memcmp(&lhs, &rhs, sizeof(sockaddr_in_t));
}

namespace UdpXactor { // namespace UdpXactor begin

UdpConnectionBase::~UdpConnectionBase()
{

}

class UdpConnection : public UdpConnectionBase
{
public:
    UdpConnection(const sockaddr_in_t & host_address, const sockaddr_in_t & peer_address, socket_t sockfd, void * user_data, bool bound);
    virtual ~UdpConnection();

public:
    virtual bool init(const FecConfiguration & fec);
    virtual void exit();

public:
    virtual bool is_listener();

public:
    virtual void set_user_data(void * user_data) override;
    virtual void * get_user_data() override;

public:
    virtual void get_host_address(std::string & ip, unsigned short & port) override;
    virtual void get_peer_address(std::string & ip, unsigned short & port) override;

public:
    sockaddr_in_t & get_address();
    socket_t get_socket();

public:
    bool has_bound();
    bool use_fec();

public:
    CauchyFecEncoder & get_fec_encoder();
    CauchyFecDecoder & get_fec_decoder();

public:
    void disable_socket();

protected:
    sockaddr_in_t                               m_host_address;
    sockaddr_in_t                               m_peer_address;

private:
    socket_t                                    m_sockfd;
    void                                      * m_user_data;
    bool                                        m_bound;

private:
    std::string                                 m_host_ip;
    std::string                                 m_peer_ip;
    unsigned short                              m_host_port;
    unsigned short                              m_peer_port;

private:
    bool                                        m_use_fec;
    CauchyFecEncoder                            m_fec_encoder;
    CauchyFecDecoder                            m_fec_decoder;
};

static bool resolve_address(const sockaddr_in_t & address, std::string & ip, unsigned short & port);

UdpConnection::UdpConnection(const sockaddr_in_t & host_address, const sockaddr_in_t & peer_address, socket_t sockfd, void * user_data, bool bound)
    : m_host_address(host_address)
    , m_peer_address(peer_address)
    , m_sockfd(sockfd)
    , m_user_data(user_data)
    , m_bound(bound)
    , m_host_ip()
    , m_peer_ip()
    , m_host_port(0)
    , m_peer_port(0)
    , m_use_fec(false)
    , m_fec_encoder()
    , m_fec_decoder()
{
    resolve_address(host_address, m_host_ip, m_host_port);
    resolve_address(peer_address, m_peer_ip, m_peer_port);
}

UdpConnection::~UdpConnection()
{
    exit();
}

bool UdpConnection::init(const FecConfiguration & fec)
{
    m_use_fec = fec.enable_fec;
    if (m_use_fec)
    {
        return m_fec_encoder.init(fec.fec_encode_max_block_size, fec.fec_encode_recovery_rate, fec.fec_encode_force_recovery) && m_fec_decoder.init(fec.fec_decode_expire_millisecond);
    }
    return true;
}

void UdpConnection::exit()
{
    memset(&m_host_address, 0x0, sizeof(m_host_address));
    memset(&m_peer_address, 0x0, sizeof(m_peer_address));
    m_sockfd = BAD_SOCKET;
    m_user_data = nullptr;
    m_bound = false;
    m_fec_encoder.exit();
    m_fec_decoder.exit();
    m_host_ip.clear();
    m_peer_ip.clear();
    m_host_port = 0;
    m_peer_port = 0;
}

bool UdpConnection::is_listener()
{
    return false;
}

void UdpConnection::set_user_data(void * user_data)
{
    m_user_data = user_data;
}

void * UdpConnection::get_user_data()
{
    return m_user_data;
}

void UdpConnection::get_host_address(std::string & ip, unsigned short & port)
{
    ip = m_host_ip;
    port = m_host_port;
}

void UdpConnection::get_peer_address(std::string & ip, unsigned short & port)
{
    ip = m_peer_ip;
    port = m_peer_port;
}

sockaddr_in_t & UdpConnection::get_address()
{
    return m_peer_address;
}

socket_t UdpConnection::get_socket()
{
    return m_sockfd;
}

bool UdpConnection::has_bound()
{
    return m_bound;
}

bool UdpConnection::use_fec()
{
    return m_use_fec;
}

CauchyFecEncoder & UdpConnection::get_fec_encoder()
{
    return m_fec_encoder;
}

CauchyFecDecoder & UdpConnection::get_fec_decoder()
{
    return m_fec_decoder;
}

void UdpConnection::disable_socket()
{
    m_sockfd = BAD_SOCKET;
}

class UdpListener : public UdpConnection
{
public:
    UdpListener(const sockaddr_in_t & host_address, bool one_to_one, socket_t sockfd, void * user_data);
    virtual ~UdpListener();

public:
    virtual bool init(const FecConfiguration & fec) override;
    virtual void exit() override;

public:
    virtual bool is_listener() override;

public:
    bool is_one_to_one();

public:
    const FecConfiguration & get_fec();

public:
    UdpConnection * get_connection(const sockaddr_in_t & address);
    bool insert_connection(const sockaddr_in_t & address, UdpConnection * connection);
    void remove_connection(UdpConnection * connection, UdpServiceBase * udp_service);
    void clear_connections(UdpServiceBase * udp_service);

public:
    UdpConnection * create_connection();
    void destroy_connection(UdpConnection * connection);

private:
    bool                                        m_one_to_one;
    FecConfiguration                            m_fec_configuration;

private:
    std::map<sockaddr_in_t, UdpConnection *>    m_connection_map;
    std::mutex                                  m_connection_mutex;
};

UdpListener::UdpListener(const sockaddr_in_t & host_address, bool one_to_one, socket_t sockfd, void * user_data)
    : UdpConnection(host_address, host_address, sockfd, user_data, false)
    , m_one_to_one(one_to_one)
    , m_fec_configuration()
    , m_connection_map()
    , m_connection_mutex()
{
    memset(&m_fec_configuration, 0x0, sizeof(m_fec_configuration));
}

UdpListener::~UdpListener()
{
    exit();
}

bool UdpListener::init(const FecConfiguration & fec)
{
    m_fec_configuration = fec;
    return true;
}

void UdpListener::exit()
{
    clear_connections(nullptr);
    m_one_to_one = false;
    memset(&m_fec_configuration, 0x0, sizeof(m_fec_configuration));
}

bool UdpListener::is_listener()
{
    return true;
}

bool UdpListener::is_one_to_one()
{
    return m_one_to_one;
}

const FecConfiguration & UdpListener::get_fec()
{
    return m_fec_configuration;
}

UdpConnection * UdpListener::create_connection()
{
    UdpConnection * connection = new UdpConnection(m_host_address, m_peer_address, get_socket(), get_user_data(), m_one_to_one);
    if (nullptr != connection)
    {
        if (!connection->init(m_fec_configuration))
        {
            delete connection;
            connection = nullptr;
        }
    }
    return connection;
}

void UdpListener::destroy_connection(UdpConnection * connection)
{
    if (nullptr != connection)
    {
        delete connection;
        connection = nullptr;
    }
}

UdpConnection * UdpListener::get_connection(const sockaddr_in_t & address)
{
    std::lock_guard<std::mutex> locker(m_connection_mutex);
    std::map<sockaddr_in_t, UdpConnection *>::iterator iter = m_connection_map.find(address);
    return m_connection_map.end() != iter ? iter->second : nullptr;
}

bool UdpListener::insert_connection(const sockaddr_in_t & address, UdpConnection * connection)
{
    std::lock_guard<std::mutex> locker(m_connection_mutex);
    return m_connection_map.insert(std::make_pair(address, connection)).second;
}

void UdpListener::remove_connection(UdpConnection * connection, UdpServiceBase * udp_service)
{
    std::lock_guard<std::mutex> locker(m_connection_mutex);
    m_connection_map.erase(connection->get_address());
    if (nullptr != udp_service)
    {
        udp_service->on_close(connection);
    }
    destroy_connection(connection);
}

void UdpListener::clear_connections(UdpServiceBase * udp_service)
{
    std::lock_guard<std::mutex> locker(m_connection_mutex);
    for (std::map<sockaddr_in_t, UdpConnection *>::iterator iter = m_connection_map.begin(); m_connection_map.end() != iter; ++iter)
    {
        UdpConnection * connection = iter->second;
        if (nullptr != udp_service)
        {
            udp_service->on_close(connection);
        }
        destroy_connection(connection);
    }
    m_connection_map.clear();
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
        return SIG_ERR;
    }
    else
    {
        return old_act.sa_handler;
    }
}
#endif // _MSC_VER

static bool init_network()
{
#ifdef _MSC_VER
    WSADATA wsa_data = { 0x0 };
    if (0 != WSAStartup(MAKEWORD(2, 2), &wsa_data))
#else
    if (SIG_ERR == safe_signal(SIGPIPE, SIG_IGN))
#endif // _MSC_VER
    {
        RUN_LOG_ERR("init network failed: %d", net_error());
        return false;
    }
    return true;
}

static bool exit_network()
{
#ifdef _MSC_VER
    if (0 != WSACleanup())
#else
    if (SIG_ERR == safe_signal(SIGPIPE, SIG_DFL))
#endif // _MSC_VER
    {
        RUN_LOG_ERR("exit network failed: %d", net_error());
        return false;
    }
    return true;
}

static bool transform_address(const char * ip, unsigned short port, sockaddr_in_t & address)
{
    if (nullptr == ip)
    {
        RUN_LOG_ERR("ip is invalid");
        return false;
    }
    memset(&address, 0x0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    return ::inet_pton(AF_INET, ip, &address.sin_addr) > 0;
}

static bool resolve_address(const sockaddr_in_t & address, std::string & ip, unsigned short & port)
{
    port = ntohs(address.sin_port);
    char buffer[16] = { 0x0 };
    if (nullptr == ::inet_ntop(AF_INET, const_cast<in_address_t *>(&address.sin_addr), buffer, sizeof(buffer)))
    {
        return false;
    }
    ip = buffer;
    return true;
}

static bool udp_open(socket_t & sockfd)
{
    sockfd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (BAD_SOCKET == sockfd)
    {
        RUN_LOG_ERR("socket failed: %d", net_error());
        return false;
    }
    return true;
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
        return false;
    }
    return true;
}

static bool udp_reuse_port(socket_t sockfd)
{
#ifndef _MSC_VER
    const int reuse_port = 1;
    if (::setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<const char *>(&reuse_port), sizeof(reuse_port)) < 0)
    {
        RUN_LOG_ERR("setsockopt(reuse-port) failed: %d", net_error());
        return false;
    }
#endif // _MSC_VER
    return true;
}

static bool udp_bind(socket_t sockfd, const sockaddr_in_t & address)
{
    if (::bind(sockfd, reinterpret_cast<sockaddr_t *>(const_cast<sockaddr_in_t *>(&address)), sizeof(address)) < 0)
    {
        RUN_LOG_ERR("bind failed: %d", net_error());
        return false;
    }
    return true;
}

static bool udp_bind(socket_t & sockfd, const sockaddr_in_t & host_address, bool reuse_addr, bool reuse_port)
{
    if (!udp_open(sockfd))
    {
        return false;
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

        return true;
    } while (false);

    udp_close(sockfd);
    sockfd = BAD_SOCKET;

    return false;
}

static bool udp_bind(socket_t & sockfd, const char * host_ip, unsigned short host_port, bool reuse_addr, bool reuse_port)
{
    if (nullptr == host_ip || 0 == host_port)
    {
        return udp_open(sockfd);
    }
    else
    {
        sockaddr_in_t host_address = { 0x0 };
        return transform_address(host_ip, host_port, host_address) && udp_bind(sockfd, host_address, reuse_addr, reuse_port);
    }
}

static bool udp_connect(socket_t sockfd, const sockaddr_in_t & peer_address)
{
    if (::connect(sockfd, reinterpret_cast<sockaddr_t *>(const_cast<sockaddr_in_t *>(&peer_address)), sizeof(peer_address)) < 0)
    {
        RUN_LOG_ERR("connect failed: %d", net_error());
        return false;
    }
    return true;
}

static bool udp_connect(socket_t & sockfd, const sockaddr_in_t & peer_address, const char * host_ip, unsigned short host_port, bool reuse_addr, bool reuse_port)
{
    if (!udp_bind(sockfd, host_ip, host_port, reuse_addr, reuse_port))
    {
        return false;
    }

    if (udp_connect(sockfd, peer_address))
    {
        return true;
    }

    udp_close(sockfd);
    sockfd = BAD_SOCKET;

    return false;
}

static bool udp_connect(socket_t & sockfd, const char * peer_ip, unsigned short peer_port, const char * host_ip, unsigned short host_port, bool reuse_addr, bool reuse_port)
{
    if (nullptr == peer_ip || 0 == peer_port)
    {
        return false;
    }
    else
    {
        sockaddr_in_t peer_address = { 0x0 };
        return transform_address(peer_ip, peer_port, peer_address) && udp_connect(sockfd, peer_address, host_ip, host_port, reuse_addr, reuse_port);
    }
}

static bool udp_send(socket_t sockfd, const sockaddr_in_t & peer_address, const char * data, std::size_t data_size)
{
    if (nullptr == data && 0 != data_size)
    {
        RUN_LOG_ERR("sendto failed: invalid data");
        return false;
    }

    sockaddr_len_t addr_len = static_cast<sockaddr_len_t>(sizeof(peer_address));
    int send_len = ::sendto(sockfd, data, static_cast<int>(data_size), 0, reinterpret_cast<const sockaddr_t *>(&peer_address), addr_len);
    if (send_len < 0 || send_len != static_cast<int>(data_size))
    {
        RUN_LOG_ERR("sendto failed: %d", net_error());
        return false;
    }

    return true;
}

static bool udp_send(socket_t sockfd, const char * data, std::size_t data_size)
{
    if (nullptr == data && 0 != data_size)
    {
        RUN_LOG_ERR("send failed: invalid data");
        return false;
    }

    int send_len = ::send(sockfd, data, static_cast<int>(data_size), 0);
    if (send_len < 0 || send_len != static_cast<int>(data_size))
    {
        RUN_LOG_ERR("send failed: %d", net_error());
        return false;
    }

    return true;
}

static bool udp_recv(socket_t sockfd, sockaddr_in_t & peer_address, char * buff, std::size_t buff_size, std::size_t & recv_size)
{
    if (nullptr == buff && 0 != buff_size)
    {
        RUN_LOG_ERR("recvfrom failed: invalid buffer");
        return false;
    }

    sockaddr_len_t addr_len = static_cast<sockaddr_len_t>(sizeof(peer_address));
    int recv_len = ::recvfrom(sockfd, buff, static_cast<int>(buff_size), 0, reinterpret_cast<sockaddr_t *>(&peer_address), &addr_len);
    if (recv_len < 0)
    {
        RUN_LOG_ERR("recvfrom failed: %d", net_error());
        return false;
    }
    recv_size = static_cast<std::size_t>(recv_len);

    return true;
}

static bool udp_recv(socket_t sockfd, char * buff, std::size_t buff_size, std::size_t & recv_size)
{
    if (nullptr == buff && 0 != buff_size)
    {
        RUN_LOG_ERR("recv failed: invalid buffer");
        return false;
    }

    int recv_len = ::recv(sockfd, buff, static_cast<int>(buff_size), 0);
    if (recv_len < 0)
    {
        RUN_LOG_ERR("recv failed: %d", net_error());
        return false;
    }
    recv_size = static_cast<std::size_t>(recv_len);

    return true;
}

static bool udp_set_block_switch(socket_t sockfd, bool blocking)
{
#ifdef _MSC_VER
    u_long non_blocking_mode = (blocking ? 0 : 1);
    int ret = ::ioctlsocket(sockfd, FIONBIO, &non_blocking_mode);
    if (ret < 0)
    {
        RUN_LOG_ERR("ioctlsocket(%s) failed: %d", (blocking ? "blocking" : "non-blocking"), net_error());
        return false;
    }
    return true;
#else
    int flags = ::fcntl(sockfd, F_GETFL, 0);
    if (flags < 0)
    {
        RUN_LOG_ERR("fcntl(get-%s-flags) failed: %d", (blocking ? "blocking" : "non-blocking"), net_error());
        return false;
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
        return false;
    }
    return true;
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
        return false;
    }
    return true;
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
        return false;
    }
    return true;
}

static bool udp_get_host_address(socket_t sockfd, sockaddr_in_t & address)
{
    sockaddr_len_t addr_len = static_cast<sockaddr_len_t>(sizeof(address));
    if (0 != ::getsockname(sockfd, reinterpret_cast<sockaddr_t *>(&address), &addr_len))
    {
        RUN_LOG_ERR("getsockname failed: %d", net_error());
        return false;
    }
    return true;
}

static bool udp_get_peer_address(socket_t sockfd, sockaddr_in_t & address)
{
    sockaddr_len_t addr_len = static_cast<sockaddr_len_t>(sizeof(address));
    if (0 != ::getpeername(sockfd, reinterpret_cast<sockaddr_t *>(&address), &addr_len))
    {
        RUN_LOG_ERR("getpeername failed: %d", net_error());
        return false;
    }
    return true;
}

static bool find_socket(std::mutex & connection_mutex, std::list<UdpConnection *> & connection_list, const sockaddr_in_t & address, socket_t & sockfd)
{
    std::lock_guard<std::mutex> locker(connection_mutex);
    for (std::list<UdpConnection *>::const_iterator iter = connection_list.begin(); connection_list.end() != iter; ++iter)
    {
        UdpConnection * connection = *iter;
        if (address == connection->get_address())
        {
            sockfd = connection->get_socket();
            return true;
        }
    }
    sockfd = BAD_SOCKET;
    return false;
}

static void insert_connection(std::mutex & connection_mutex, std::list<UdpConnection *> & connection_list, UdpConnection * connection)
{
    std::lock_guard<std::mutex> locker(connection_mutex);
    if (connection->is_listener())
    {
        connection_list.push_front(connection);
    }
    else
    {
        connection_list.push_back(connection);
    }
}

static bool remove_connection(std::mutex & connection_mutex, std::list<UdpConnection *> & connection_list, UdpConnection * connection, UdpServiceBase * udp_service)
{
    if (nullptr == connection || nullptr == udp_service)
    {
        return false;
    }
    std::lock_guard<std::mutex> locker(connection_mutex);
    for (std::list<UdpConnection *>::iterator iter = connection_list.begin(); connection_list.end() != iter; ++iter)
    {
        if (connection->is_listener())
        {
            if (connection != *iter)
            {
                continue;
            }
            UdpListener * listener = reinterpret_cast<UdpListener *>(connection);
            listener->clear_connections(udp_service);
        }
        else if (connection->has_bound())
        {
            if (connection != *iter)
            {
                continue;
            }
            udp_service->on_close(connection);
        }
        else
        {
            if (!(*iter)->is_listener())
            {
                break;
            }
            if ((*iter)->get_socket() != connection->get_socket())
            {
                continue;
            }
            UdpListener * listener = reinterpret_cast<UdpListener *>(*iter);
            listener->remove_connection(connection, udp_service);
            return true;
        }
        udp_close(connection->get_socket());
        connection_list.erase(iter);
        delete connection;
        return true;
    }
    return false;
}

static void clear_connections(std::mutex & connection_mutex, std::list<UdpConnection *> & connection_list, UdpServiceBase * udp_service)
{
    std::lock_guard<std::mutex> locker(connection_mutex);
    for (std::list<UdpConnection *>::iterator iter = connection_list.begin(); connection_list.end() != iter; ++iter)
    {
        UdpConnection * connection = *iter;
        if (connection->is_listener())
        {
            UdpListener * listener = reinterpret_cast<UdpListener *>(connection);
            listener->clear_connections(udp_service);
        }
        else
        {
            udp_service->on_close(connection);
        }
        udp_close(connection->get_socket());
        delete connection;
    }
    connection_list.clear();
}

static UdpConnection * handle_connect_request(xactor_t xactor, std::mutex & connection_mutex, std::list<UdpConnection *> & connection_list, UdpListener * listener, UdpServiceBase * udp_service)
{
    if (BAD_XACTOR == xactor || nullptr == listener || nullptr == udp_service)
    {
        return nullptr;
    }

    UdpConnection * connection = (listener->is_one_to_one() ? nullptr : listener->get_connection(listener->get_address()));
    if (nullptr != connection)
    {
        udp_send(connection->get_socket(), connection->get_address(), nullptr, 0);
        return nullptr;
    }

    connection = listener->create_connection();
    if (nullptr == connection)
    {
        return nullptr;
    }

    if (!connection->init(listener->get_fec()))
    {
        listener->destroy_connection(connection);
        return nullptr;
    }

    if (!listener->is_one_to_one())
    {
        if (listener->insert_connection(listener->get_address(), connection))
        {
            udp_send(connection->get_socket(), connection->get_address(), nullptr, 0);
            udp_service->on_listen(connection, connection->get_user_data());
        }
        else
        {
            listener->destroy_connection(connection);
        }
        return nullptr;
    }

    if (!udp_connect(connection->get_socket(), connection->get_address()))
    {
        listener->destroy_connection(connection);
        return nullptr;
    }

    listener->disable_socket();

    remove_connection(connection_mutex, connection_list, listener, udp_service);

    insert_connection(connection_mutex, connection_list, connection);

    udp_service->on_listen(connection, connection->get_user_data());

    udp_send(connection->get_socket(), nullptr, 0);

    return connection;
}

static bool handle_recv_data(UdpConnection * connection, const void * data, std::size_t size, UdpServiceBase * udp_service)
{
    if (nullptr == connection || nullptr == data || nullptr == udp_service)
    {
        return false;
    }

    socket_t sockfd = connection->get_socket();
    if (BAD_SOCKET == sockfd)
    {
        return false;
    }

    if (connection->is_listener())
    {
        UdpListener * listener = reinterpret_cast<UdpListener *>(connection);
        connection = listener->get_connection(listener->get_address());
        if (nullptr == connection)
        {
            return false;
        }
    }

    if (connection->use_fec())
    {
        std::list<std::vector<uint8_t>> dst_list;
        CauchyFecDecoder & fec_decoder = connection->get_fec_decoder();
        if (!fec_decoder.decode(reinterpret_cast<const uint8_t *>(data), static_cast<uint32_t>(size), dst_list))
        {
            return false;
        }

        for (std::list<std::vector<uint8_t>>::const_iterator iter = dst_list.begin(); dst_list.end() != iter; ++iter)
        {
            const std::vector<uint8_t> & piece = *iter;
            udp_service->on_recv(connection, reinterpret_cast<const char *>(&piece[0]), piece.size());
        }
    }
    else
    {
        udp_service->on_recv(connection, data, size);
    }
    return true;
}

static bool handle_send_data(UdpConnection * connection, const void * data, std::size_t size)
{
    if (nullptr == connection || connection->is_listener() || nullptr == data)
    {
        return false;
    }

    socket_t sockfd = connection->get_socket();
    if (BAD_SOCKET == sockfd)
    {
        return false;
    }

    const sockaddr_in_t & address = connection->get_address();
    bool bound = connection->has_bound();

    if (connection->use_fec() && 0 != size)
    {
        std::list<std::vector<uint8_t>> dst_list;
        CauchyFecEncoder & fec_encoder = connection->get_fec_encoder();
        if (!fec_encoder.encode(reinterpret_cast<const uint8_t *>(data), static_cast<uint32_t>(size), dst_list))
        {
            return false;
        }

        bool ret = !dst_list.empty();
        for (std::list<std::vector<uint8_t>>::const_iterator iter = dst_list.begin(); dst_list.end() != iter; ++iter)
        {
            const std::vector<uint8_t> & piece = *iter;
            if (bound)
            {
                if (!udp_send(sockfd, reinterpret_cast<const char *>(&piece[0]), piece.size()))
                {
                    ret = false;
                }
            }
            else
            {
                if (!udp_send(sockfd, address, reinterpret_cast<const char *>(&piece[0]), piece.size()))
                {
                    ret = false;
                }
            }
        }
        return ret;
    }
    else
    {
        if (bound)
        {
            return udp_send(sockfd, reinterpret_cast<const char *>(data), size);
        }
        else
        {
            return udp_send(sockfd, address, reinterpret_cast<const char *>(data), size);
        }
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
        return false;
    }
    event = new iocp_event_t;
    if (nullptr == event)
    {
        RUN_LOG_ERR("create event failed");
        return false;
    }
    memset(&event->overlapped, 0x0, sizeof(event->overlapped));
    memset(event->buffer, 0x0, sizeof(event->buffer));
    event->buffer_size = sizeof(event->buffer) / sizeof(event->buffer[0]);
    event->data.buf = event->buffer;
    event->data.len = static_cast<ULONG>(event->buffer_size);
    event->connection = connection;
    return true;
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
        return false;
    }
    return true;
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
        return false;
    }
    if (nullptr == ::CreateIoCompletionPort(reinterpret_cast<HANDLE>(event->connection->get_socket()), iocp_handle, reinterpret_cast<ULONG_PTR>(event), 0))
    {
        RUN_LOG_ERR("append to iocp failed: %d", net_error());
        return false;
    }
    return true;
}

static bool post_recv(iocp_event_t * event)
{
    if (nullptr == event || nullptr == event->connection || BAD_SOCKET == event->connection->get_socket())
    {
        return false;
    }
    WSABUF buffer_array[1] = { event->data };
    DWORD recv_len = 0;
    DWORD recv_flg = 0;
    if (event->connection->is_listener())
    {
        sockaddr_in_t & address = event->connection->get_address();
        INT addr_len = sizeof(address);
        if (SOCKET_ERROR == ::WSARecvFrom(event->connection->get_socket(), buffer_array, 1, &recv_len, &recv_flg, reinterpret_cast<sockaddr_t *>(&address), &addr_len, &event->overlapped, nullptr))
        {
            if (WSA_IO_PENDING != net_error())
            {
                RUN_LOG_ERR("post recv failed: %d", net_error());
                return false;
            }
        }
    }
    else
    {
        if (SOCKET_ERROR == ::WSARecv(event->connection->get_socket(), buffer_array, 1, &recv_len, &recv_flg, &event->overlapped, nullptr))
        {
            if (WSA_IO_PENDING != net_error())
            {
                RUN_LOG_ERR("post recv failed: %d", net_error());
                return false;
            }
        }
    }
    return true;
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
    return create_iocp(xactor);
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
        return false;
    }

    iocp_event_t * event = nullptr;
    if (!create_event(connection, event))
    {
        return false;
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

        return true;
    } while (false);

    destroy_event(event);

    return false;
}

static void handle_recv(volatile bool & running, xactor_t xactor, std::mutex & connection_mutex, std::list<UdpConnection *> & connection_list, UdpServiceBase * udp_service)
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

        const char * data = event->buffer;
        UdpConnection * connection = event->connection;

        if (good)
        {
            if (nullptr != connection)
            {
                if (0 == data_len)
                {
                    if (connection->is_listener())
                    {
                        UdpConnection * new_connection = handle_connect_request(xactor, connection_mutex, connection_list, reinterpret_cast<UdpListener *>(connection), udp_service);
                        if (nullptr != new_connection)
                        {
                            event->connection = new_connection;
                            connection = new_connection;
                        }
                    }
                    else
                    {
                        udp_send(connection->get_socket(), nullptr, 0);
                    }
                }
                else
                {
                    handle_recv_data(connection, data, data_len, udp_service);
                }
            }
            if (good)
            {
                good = post_recv(event);
            }
        }

        if (!good)
        {
            if (ERROR_SUCCESS != net_error() && ERROR_NETNAME_DELETED != net_error() && ERROR_CONNECTION_ABORTED != net_error())
            {
                RUN_LOG_ERR("iocp error: %d", net_error());
            }
            remove_connection(connection_mutex, connection_list, connection, udp_service);
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
        return false;
    }
    return true;
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
        return false;
    }
    struct epoll_event event = { 0x0 };
    event.data.ptr = connection;
    event.events = EPOLLIN | EPOLLET;
    if (-1 == ::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, connection->get_socket(), &event))
    {
        RUN_LOG_ERR("append to epoll failed: %d", net_error());
        return false;
    }
    return true;
}

static bool delete_from_epoll(int epoll_fd, UdpConnection * connection)
{
    if (-1 == epoll_fd || nullptr == connection || BAD_SOCKET == connection->get_socket())
    {
        return false;
    }
    struct epoll_event event = { 0x0 };
    if (-1 == ::epoll_ctl(epoll_fd, EPOLL_CTL_DEL, connection->get_socket(), &event))
    {
        RUN_LOG_ERR("delete from epoll failed: %d", net_error());
        return false;
    }
    return true;
}

static bool post_recv(int epoll_fd, UdpConnection * connection)
{
    if (-1 == epoll_fd || nullptr == connection || BAD_SOCKET == connection->get_socket())
    {
        return false;
    }
    struct epoll_event event = { 0x0 };
    event.data.ptr = connection;
    event.events = EPOLLIN | EPOLLET;
    if (-1 == ::epoll_ctl(epoll_fd, EPOLL_CTL_MOD, connection->get_socket(), &event))
    {
        RUN_LOG_ERR("post recv failed: %d", net_error());
        return false;
    }
    return true;
}

static bool create_xactor(xactor_t & xactor)
{
    return create_epoll(xactor);
}

static void destroy_xactor(xactor_t & xactor, std::size_t handle_thread_count)
{
    destroy_epoll(xactor);
}

static bool append_to_xactor(xactor_t xactor, UdpConnection * connection)
{
    return append_to_epoll(xactor, connection);
}

static void handle_recv(volatile bool & running, xactor_t xactor, std::mutex & connection_mutex, std::list<UdpConnection *> & connection_list, UdpServiceBase * udp_service)
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
                if (connection->is_listener())
                {
                    if (udp_recv(connection->get_socket(), connection->get_address(), buffer, sizeof(buffer), recv_size))
                    {
                        if (0 == recv_size)
                        {
                            UdpConnection * new_connection = handle_connect_request(xactor, connection_mutex, connection_list, reinterpret_cast<UdpListener *>(connection), udp_service);
                            if (nullptr != new_connection)
                            {
                                connection = new_connection;
                            }
                        }
                        else
                        {
                            handle_recv_data(connection, buffer, recv_size, udp_service);
                        }
                    }
                }
                else
                {
                    if (udp_recv(connection->get_socket(), buffer, sizeof(buffer), recv_size))
                    {
                        if (0 == recv_size)
                        {
                            udp_send(connection->get_socket(), nullptr, 0);
                        }
                        else
                        {
                            handle_recv_data(connection, buffer, recv_size, udp_service);
                        }
                    }
                }
                if (good)
                {
                    good = post_recv(xactor, connection);
                }
            }
            if (!good)
            {
                delete_from_epoll(xactor, connection);
                remove_connection(connection_mutex, connection_list, connection, udp_service);
            }
        }
    }
}

#endif // _MSC_VER

UdpServiceBase::~UdpServiceBase()
{

}

class UdpManagerImpl
{
public:
    UdpManagerImpl();
    ~UdpManagerImpl();

public:
    bool init(UdpServiceBase * udp_service, const FecConfiguration * fec, std::size_t thread_count);
    void exit();

public:
    bool listen(const char * host_ip, unsigned short host_port, void * user_data, bool one_to_one, bool reuse_addr, bool reuse_port);
    bool accept(const char * host_ip, unsigned short host_port, void * user_data, bool reuse_addr, bool reuse_port);
    bool connect(const char * peer_ip, unsigned short peer_port, void * user_data, const char * host_ip, unsigned short host_port, bool reuse_addr, bool reuse_port);
    bool send(UdpConnectionBase * connection, const void * data, std::size_t size);
    bool close(UdpConnectionBase * connection);

private:
    void do_accept(socket_t listener, void * user_data);

private:
    volatile bool                                       m_running;
    FecConfiguration                                    m_fec;
    xactor_t                                            m_xactor;
    UdpServiceBase                                    * m_udp_service;

private:
    std::list<sockaddr_in_t>                            m_accept_addresses;
    std::list<std::thread>                              m_accept_threads;
    std::mutex                                          m_accept_mutex;

private:
    std::vector<std::thread>                            m_recv_threads;

private:
    std::list<UdpConnection *>                          m_connection_list;
    std::mutex                                          m_connection_mutex;
};

UdpManagerImpl::UdpManagerImpl()
    : m_running(false)
    , m_fec()
    , m_xactor(BAD_XACTOR)
    , m_udp_service(nullptr)
    , m_accept_addresses()
    , m_accept_threads()
    , m_accept_mutex()
    , m_recv_threads()
    , m_connection_list()
    , m_connection_mutex()
{
    memset(&m_fec, 0x0, sizeof(m_fec));
}

UdpManagerImpl::~UdpManagerImpl()
{
    exit();
}

bool UdpManagerImpl::init(UdpServiceBase * udp_service, const FecConfiguration * fec, std::size_t thread_count)
{
    exit();

    m_running = true;

    if (nullptr != fec)
    {
        m_fec = *fec;
    }

    if (nullptr == udp_service)
    {
        RUN_LOG_ERR("udp manager init failure while udp service is invalid");
        return false;
    }

    m_udp_service = udp_service;

    if (!init_network())
    {
        RUN_LOG_ERR("udp manager init failure while init network failed");
        return false;
    }

    if (!create_xactor(m_xactor))
    {
        RUN_LOG_ERR("udp manager init failure while create xactor failed");
        return false;
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
        std::thread recv_thread(&handle_recv, std::ref(m_running), std::ref(m_xactor), std::ref(m_connection_mutex), std::ref(m_connection_list), m_udp_service);
        if (!recv_thread.joinable())
        {
            RUN_LOG_ERR("udp manager init failure while create recv thread failed");
            return false;
        }
        m_recv_threads.emplace_back(std::move(recv_thread));
    }

    return true;
}

void UdpManagerImpl::exit()
{
    if (m_running)
    {
        m_running = false;

        {
            std::lock_guard<std::mutex> locker(m_accept_mutex);
            if (!m_accept_threads.empty())
            {
                socket_t sockfd = BAD_SOCKET;
                if (udp_open(sockfd))
                {
                    for (std::list<sockaddr_in_t>::const_iterator iter = m_accept_addresses.begin(); m_accept_addresses.end() != iter; ++iter)
                    {
                        const sockaddr_in_t & accept_address = *iter;
                        udp_send(sockfd, accept_address, nullptr, 0);
                    }
                    m_accept_addresses.clear();
                    udp_close(sockfd);
                    sockfd = BAD_SOCKET;
                }

                for (std::list<std::thread>::iterator iter = m_accept_threads.begin(); m_accept_threads.end() != iter; ++iter)
                {
                    iter->join();
                }
                m_accept_threads.clear();
            }
        }

        destroy_xactor(m_xactor, m_recv_threads.size());

        for (std::vector<std::thread>::iterator iter = m_recv_threads.begin(); m_recv_threads.end() != iter; ++iter)
        {
            iter->join();
        }
        m_recv_threads.clear();

        clear_connections(m_connection_mutex, m_connection_list, m_udp_service);

        memset(&m_fec, 0x0, sizeof(m_fec));
        m_udp_service = nullptr;

        exit_network();
    }
}

bool UdpManagerImpl::listen(const char * host_ip, unsigned short host_port, void * user_data, bool one_to_one, bool reuse_addr, bool reuse_port)
{
    if (!m_running || nullptr == m_udp_service)
    {
        return false;
    }

    if (nullptr == host_ip)
    {
        host_ip = "0.0.0.0";
    }

    if (0 == host_port)
    {
        return false;
    }

    socket_t acceptor = BAD_SOCKET;
    if (!udp_bind(acceptor, host_ip, host_port, reuse_addr, reuse_port))
    {
        return false;
    }

    UdpListener * listener = nullptr;

    do
    {
        if (!udp_set_block_switch(acceptor, false))
        {
            break;
        }

        sockaddr_in_t host_address = { 0x0 };
        if (!udp_get_host_address(acceptor, host_address))
        {
            break;
        }

        listener = new UdpListener(host_address, one_to_one, acceptor, user_data);
        if (nullptr == listener)
        {
            break;
        }

        if (!listener->init(m_fec))
        {
            break;
        }

        insert_connection(m_connection_mutex, m_connection_list, listener);

        if (!append_to_xactor(m_xactor, listener))
        {
            remove_connection(m_connection_mutex, m_connection_list, listener, m_udp_service);
            return false;
        }

        return true;
    } while (false);

    if (nullptr != listener)
    {
        delete listener;
        listener = nullptr;
    }

    udp_close(acceptor);
    acceptor = BAD_SOCKET;

    return false;
}

bool UdpManagerImpl::accept(const char * host_ip, unsigned short host_port, void * user_data, bool reuse_addr, bool reuse_port)
{
    if (!m_running || nullptr == m_udp_service)
    {
        return false;
    }

    if (nullptr == host_ip)
    {
        host_ip = "0.0.0.0";
    }

    if (0 == host_port)
    {
        return false;
    }

    socket_t listener = BAD_SOCKET;
    if (!udp_bind(listener, host_ip, host_port, reuse_addr, reuse_port))
    {
        return false;
    }

    sockaddr_in_t host_address = { 0x0 };
    if (!udp_get_host_address(listener, host_address))
    {
        return false;
    }

    {
        std::lock_guard<std::mutex> locker(m_accept_mutex);
        std::thread accept_thread(&UdpManagerImpl::do_accept, this, listener, user_data);
        if (!accept_thread.joinable())
        {
            return false;
        }
        m_accept_addresses.push_back(host_address);
        m_accept_threads.emplace_back(std::move(accept_thread));
    }

    return true;
}

void UdpManagerImpl::do_accept(socket_t listener, void * user_data)
{
    while (m_running)
    {
        sockaddr_in_t recv_address = { 0x0 };
        std::size_t recv_size = 0;
        if (!udp_recv(listener, recv_address, nullptr, 0, recv_size))
        {
            continue;
        }

        if (!m_running)
        {
            break;
        }

        socket_t connector = BAD_SOCKET;
        if (find_socket(m_connection_mutex, m_connection_list, recv_address, connector))
        {
            udp_send(connector, nullptr, 0);
            continue;
        }

        if (!udp_open(connector))
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
            sockaddr_in_t host_address = { 0x0 };
            if (!udp_get_host_address(connector, host_address))
            {
                break;
            }

            connection = new UdpConnection(host_address, recv_address, connector, user_data, true);
            if (nullptr == connection)
            {
                break;
            }

            if (!connection->init(m_fec))
            {
                break;
            }

            insert_connection(m_connection_mutex, m_connection_list, connection);

            m_udp_service->on_accept(connection, connection->get_user_data());

            if (!append_to_xactor(m_xactor, connection))
            {
                remove_connection(m_connection_mutex, m_connection_list, connection, m_udp_service);
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

bool UdpManagerImpl::connect(const char * peer_ip, unsigned short peer_port, void * user_data, const char * host_ip, unsigned short host_port, bool reuse_addr, bool reuse_port)
{
    if (!m_running || nullptr == m_udp_service)
    {
        return false;
    }

    sockaddr_in_t peer_address = { 0x0 };
    if (!transform_address(peer_ip, peer_port, peer_address))
    {
        return false;
    }

    socket_t connector = BAD_SOCKET;
    if (!udp_bind(connector, host_ip, host_port, reuse_addr, reuse_port))
    {
        return false;
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

        connection = new UdpConnection(host_address, recv_address, connector, user_data, true);
        if (nullptr == connection)
        {
            break;
        }

        if (!connection->init(m_fec))
        {
            break;
        }

        insert_connection(m_connection_mutex, m_connection_list, connection);

        m_udp_service->on_connect(connection, user_data);

        if (!append_to_xactor(m_xactor, connection))
        {
            remove_connection(m_connection_mutex, m_connection_list, connection, m_udp_service);
            return false;
        }

        return true;
    } while (false);

    if (nullptr != connection)
    {
        delete connection;
        connection = nullptr;
    }

    udp_close(connector);
    connector = BAD_SOCKET;

    return false;
}

bool UdpManagerImpl::send(UdpConnectionBase * connection, const void * data, std::size_t size)
{
    return handle_send_data(reinterpret_cast<UdpConnection *>(connection), data, size);
}

bool UdpManagerImpl::close(UdpConnectionBase * connection)
{
    return nullptr != connection && remove_connection(m_connection_mutex, m_connection_list, reinterpret_cast<UdpConnection *>(connection), m_udp_service);
}

UdpManager::UdpManager()
    : m_manager_impl(nullptr)
{

}

UdpManager::~UdpManager()
{
    exit();
}

bool UdpManager::init(UdpServiceBase * udp_service, const FecConfiguration * fec, std::size_t thread_count)
{
    if (nullptr == udp_service)
    {
        return false;
    }

    if (nullptr != m_manager_impl)
    {
        return false;
    }

    m_manager_impl = new UdpManagerImpl;
    if (nullptr == m_manager_impl)
    {
        return false;
    }

    if (m_manager_impl->init(udp_service, fec, thread_count))
    {
        return true;
    }

    delete m_manager_impl;
    m_manager_impl = nullptr;

    return false;
}

void UdpManager::exit()
{
    if (nullptr != m_manager_impl)
    {
        m_manager_impl->exit();
        delete m_manager_impl;
        m_manager_impl = nullptr;
    }
}

bool UdpManager::listen(const char * host_ip, unsigned short host_port, void * user_data, bool one_to_one, bool reuse_addr, bool reuse_port)
{
    return nullptr != m_manager_impl && m_manager_impl->listen(host_ip, host_port, user_data, one_to_one, reuse_addr, reuse_port);
}

bool UdpManager::accept(const char * host_ip, unsigned short host_port, void * user_data, bool reuse_addr, bool reuse_port)
{
    return nullptr != m_manager_impl && m_manager_impl->accept(host_ip, host_port, user_data, reuse_addr, reuse_port);
}

bool UdpManager::connect(const char * peer_ip, unsigned short peer_port, void * user_data, const char * host_ip, unsigned short host_port, bool reuse_addr, bool reuse_port)
{
    return nullptr != m_manager_impl && m_manager_impl->connect(peer_ip, peer_port, user_data, host_ip, host_port, reuse_addr, reuse_port);
}

bool UdpManager::send(UdpConnectionBase * connection, const void * data, std::size_t size)
{
    return nullptr != m_manager_impl && m_manager_impl->send(connection, data, size);
}

bool UdpManager::close(UdpConnectionBase * connection)
{
    return nullptr != m_manager_impl && m_manager_impl->close(connection);
}

} // namespace UdpXactor end
