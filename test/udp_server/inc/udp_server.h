/********************************************************
 * Description : udp server
 * Author      : ryan
 * Email       : ryan@rayvision.com
 * Version     : 1.0
 * History     :
 * Copyright(C): RAYVISION
 ********************************************************/

#ifndef UDP_SERVER_H
#define UDP_SERVER_H


#include <map>
#include <mutex>
#include <atomic>
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

class UdpTestServer : public UdpXactor::UdpServiceBase
{
public:
    UdpTestServer();
    virtual ~UdpTestServer() override;

public:
    bool init(const char * ip, uint16_t port, uint16_t thread_count, bool use_fec, bool send_back, bool use_listen);
    void exit();

public:
    virtual void on_listen(UdpXactor::UdpConnectionBase * connection, void * user_data) override;
    virtual void on_accept(UdpXactor::UdpConnectionBase * connection, void * user_data) override;
    virtual void on_connect(UdpXactor::UdpConnectionBase * connection, void * user_data) override;
    virtual void on_recv(UdpXactor::UdpConnectionBase * connection, const void * data, std::size_t size) override;
    virtual void on_close(UdpXactor::UdpConnectionBase * connection) override;

private:
    bool send_data(UdpXactor::UdpConnectionBase * connection, const void * data, std::size_t size);
    bool recv_data(UdpXactor::UdpConnectionBase * connection, const void * data, std::size_t size);

private:
    bool                                                        m_running;
    UdpXactor::FecConfiguration                                 m_fec;
    UdpXactor::UdpManager                                       m_manager;
    bool                                                        m_send_back;
    std::atomic<uint64_t>                                       m_session_index;
    std::map<UdpXactor::UdpConnectionBase *, session_data_t>    m_user_data_map;
    std::mutex                                                  m_user_data_mutex;
};


#endif // UDP_SERVER_H
