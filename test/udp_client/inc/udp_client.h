/********************************************************
 * Description : udp client
 * Author      : yanrk
 * Email       : yanrkchina@163.com
 * Version     : 1.0
 * History     :
 * Copyright(C): 2025
 ********************************************************/

#ifndef UDP_CLIENT_H
#define UDP_CLIENT_H


#include <map>
#include <mutex>
#include <thread>
#include <vector>
#include "udp_xactor.h"

struct speed_data_t
{
    std::chrono::system_clock::time_point   t0;
    std::chrono::system_clock::time_point   t1;
    uint64_t                                d;
    int                                     times;
    uint64_t                                count;

    speed_data_t()
        : t0(std::chrono::system_clock::now())
        , t1(t0)
        , d(0)
        , times(0)
        , count(0)
    {

    }
};

struct session_data_t
{
    uint64_t                                user_data;
    speed_data_t                            send_speed;
    speed_data_t                            recv_speed;

    session_data_t()
        : user_data(0)
        , send_speed()
        , recv_speed()
    {

    }
};

class UdpTestClient : public UdpXactor::UdpServiceBase
{
public:
    UdpTestClient();
    virtual ~UdpTestClient() override;

public:
    bool init(const char * peer_ip, unsigned short peer_port, std::size_t thread_count, std::size_t connection_count, bool use_fec);
    void exit();

public:
    virtual void on_listen(UdpXactor::UdpConnectionBase * connection, void * user_data) override;
    virtual void on_accept(UdpXactor::UdpConnectionBase * connection, void * user_data) override;
    virtual void on_connect(UdpXactor::UdpConnectionBase * connection, void * user_data) override;
    virtual void on_recv(UdpXactor::UdpConnectionBase * connection, const void * data, std::size_t size) override;
    virtual void on_close(UdpXactor::UdpConnectionBase * connection) override;

private:
    bool send_data(UdpXactor::UdpConnectionBase * connection);
    bool recv_data(UdpXactor::UdpConnectionBase * connection, const void * data, std::size_t size);

private:
    bool                                                        m_running;
    UdpXactor::FecConfiguration                                 m_fec;
    UdpXactor::UdpManager                                       m_manager;
    std::vector<std::thread>                                    m_thread_vector;
    std::map<UdpXactor::UdpConnectionBase *, session_data_t>    m_user_data_map;
    std::mutex                                                  m_user_data_mutex;
};


#endif // UDP_CLIENT_H
