/********************************************************
 * Description : udp server
 * Author      : ryan
 * Email       : ryan@rayvision.com
 * Version     : 1.0
 * History     :
 * Copyright(C): RAYVISION
 ********************************************************/

#include <cstring>
#include <chrono>
#include <iostream>
#include <functional>
#include "udp_server.h"

#ifdef _MSC_VER
    #define snprintf _snprintf_s
#endif // _MSC_VER

UdpTestServer::UdpTestServer()
    : m_running(false)
    , m_need_codec(false)
    , m_xactor(nullptr)
    , m_send_back(false)
    , m_session_index(0)
    , m_user_data_map()
    , m_user_data_mutex()
{

}

UdpTestServer::~UdpTestServer()
{
    exit();
}

bool UdpTestServer::init(const char * ip, uint16_t port, uint16_t thread_count, bool need_codec, bool send_back)
{
    exit();

    do
    {
        m_send_back = send_back;

        m_need_codec = need_codec;

        m_session_index = 0;

        if (!init_network())
        {
            std::cout << "udp test server init failure while network init failed" << std::endl;
            break;
        }

        m_xactor = create_udp_xactor();
        if (nullptr == m_xactor)
        {
            std::cout << "udp test server init failure while udp xactor create failed" << std::endl;
            break;
        }

        if (!m_xactor->init(this, thread_count, ip, port, true, true))
        {
            std::cout << "udp test server init failure while udp xactor init failed" << std::endl;
            break;
        }

        std::cout << "udp test server init success" << std::endl;

        return (true);

    } while (false);

    exit();

    return (false);
}

void UdpTestServer::exit()
{
    if (m_running)
    {
        m_running = false;

        destroy_udp_xactor(m_xactor);
        m_xactor = nullptr;

        m_user_data_map.clear();

        exit_network();
    }
}

void UdpTestServer::on_accept(socket_t sockfd)
{
    std::lock_guard<std::mutex> locker(m_user_data_mutex);
    session_data_t & session_data = m_user_data_map[sockfd];
    session_data.user_data = ++m_session_index;
    session_data.need_codec = m_need_codec;
    std::cout << "connection [" << session_data.user_data << "] incoming" << std::endl;
}

void UdpTestServer::on_connect(socket_t sockfd, uint64_t user_data)
{
    std::lock_guard<std::mutex> locker(m_user_data_mutex);
    std::cout << "invalid connection" << std::endl;
}

void UdpTestServer::on_recv(socket_t sockfd, const void * data, std::size_t data_len)
{
    recv_data(sockfd, data, data_len);
}

void UdpTestServer::on_close(socket_t sockfd)
{
    std::lock_guard<std::mutex> locker(m_user_data_mutex);
    session_data_t & session_data = m_user_data_map[sockfd];
    std::cout << "connection [" << session_data.user_data << "] outgoing" << std::endl;
    m_user_data_map.erase(sockfd);
}

void calc_speed(uint64_t session_id, speed_data_t & speed_data, bool inbound, std::size_t data_len, std::mutex & mutex)
{
    std::chrono::system_clock::time_point & t0 = speed_data.t0;
    std::chrono::system_clock::time_point & t1 = speed_data.t1;
    uint64_t & d = speed_data.d;
    int & times = speed_data.times;

    d += data_len;

    std::chrono::system_clock::time_point t2 = std::chrono::system_clock::now();
    uint64_t s = std::chrono::duration_cast<std::chrono::seconds>(t2 - t1).count();
    if (s >= 5)
    {
        ++times;
        uint64_t sp = d * 1000000 / std::chrono::duration_cast<std::chrono::microseconds>(t2 - t0).count();
        char speed[128] = { 0x0 };
        if (sp < 970.f)
        {
            snprintf(speed, sizeof(speed), "%d%s", static_cast<int>(sp), "B/S");
        }
        else if (sp < 5.f * 1024.f)
        {
            snprintf(speed, sizeof(speed), "%.2f%s", sp / 1024.f, "KB/S");
        }
        else if (sp < 970.f * 1024.f)
        {
            snprintf(speed, sizeof(speed), "%d%s", static_cast<int>(sp / 1024.f), "KB/S");
        }
        else
        {
            snprintf(speed, sizeof(speed), "%.2f%s", sp / (1024.f * 1024.f), "MB/S");
        }
        t1 = t2;
        if (times > 30)
        {
            times = 0;
            t0 = t1 = t2;
            d = 0;
        }

        {
            std::lock_guard<std::mutex> locker(mutex);
            std::cout << "session (" << session_id << ") " << (inbound ? "recv" : "send") << " speed: " << speed << std::endl;
        }
    }
}

bool UdpTestServer::send_data(socket_t sockfd, const void * data, std::size_t data_len)
{
    session_data_t * session_data = nullptr;
    {
    //  std::lock_guard<std::mutex> locker(m_user_data_mutex);
        session_data = &m_user_data_map[sockfd];
    }

    if (nullptr == session_data)
    {
        return (false);
    }

    if (!m_xactor->send(sockfd, data, data_len))
    {
        return (false);
    }

    calc_speed(session_data->user_data, session_data->send_speed, false, data_len, m_user_data_mutex);

    return (true);
}

bool UdpTestServer::recv_data(socket_t sockfd, const void * data, std::size_t data_len)
{
    session_data_t * session_data = nullptr;
    {
    //  std::lock_guard<std::mutex> locker(m_user_data_mutex);
        session_data = &m_user_data_map[sockfd];
    }

    if (nullptr == session_data)
    {
        return (false);
    }

    if (session_data->need_codec)
    {
        std::list<std::vector<uint8_t>> dst_data_list;
        if (cm256_decode(data, data_len, session_data->recv_frame.frames, dst_data_list, 1000 * 15, false))
        {
            for (std::list<std::vector<uint8_t>>::const_iterator iter = dst_data_list.begin(); dst_data_list.end() != iter; ++iter)
            {
                calc_speed(session_data->user_data, session_data->recv_speed, true, iter->size(), m_user_data_mutex);
            }
        }
    }
    else
    {
        calc_speed(session_data->user_data, session_data->recv_speed, true, data_len, m_user_data_mutex);
    }

    if (m_send_back)
    {
        send_data(sockfd, data, data_len);
    }

    return (true);
}
