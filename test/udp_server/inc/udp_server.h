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
#include "cm256_codec.h"

struct send_frame_t
{
    uint16_t                                frame_index;
    uint8_t                                 frame_filter;

    send_frame_t()
        : frame_index(0)
        , frame_filter(0)
    {

    }
};

struct recv_frame_t
{
    frames_t                                frames;

    recv_frame_t()
        : frames()
    {

    }
};

struct speed_data_t
{
    std::chrono::system_clock::time_point   t0;
    std::chrono::system_clock::time_point   t1;
    uint64_t                                d;
    int                                     times;

    speed_data_t()
        : t0(std::chrono::system_clock::now())
        , t1(t0)
        , d(0)
        , times(0)
    {

    }
};

struct session_data_t
{
    uint64_t                                user_data;
    speed_data_t                            send_speed;
    speed_data_t                            recv_speed;
    bool                                    need_codec;
    send_frame_t                            send_frame;
    recv_frame_t                            recv_frame;

    session_data_t()
        : user_data(0)
        , send_speed()
        , recv_speed()
        , need_codec(false)
        , send_frame()
        , recv_frame()
    {

    }
};

class UdpTestServer : public IUdpSink
{
public:
    UdpTestServer();
    virtual ~UdpTestServer() override;

public:
    bool init(const char * ip, uint16_t port, uint16_t thread_count, bool need_codec, bool send_back);
    void exit();

public:
    virtual void on_accept(socket_t sockfd) override;
    virtual void on_connect(socket_t sockfd, uint64_t user_data) override;
    virtual void on_recv(socket_t sockfd, const void * data, std::size_t data_len) override;
    virtual void on_close(socket_t sockfd) override;

private:
    bool send_data(socket_t sockfd, const void * data, std::size_t data_len);
    bool recv_data(socket_t sockfd, const void * data, std::size_t data_len);

private:
    bool                                    m_running;
    bool                                    m_need_codec;
    IUdpXactor                            * m_xactor;
    bool                                    m_send_back;
    std::atomic<uint64_t>                   m_session_index;
    std::map<socket_t, session_data_t>      m_user_data_map;
    std::mutex                              m_user_data_mutex;
};


#endif // UDP_SERVER_H
