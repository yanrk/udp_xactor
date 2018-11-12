/********************************************************
 * Description : udp client
 * Author      : ryan
 * Email       : ryan@rayvision.com
 * Version     : 1.0
 * History     :
 * Copyright(C): RAYVISION
 ********************************************************/

#include <ctime>
#include <cstring>
#include <chrono>
#include <iostream>
#include <functional>
#include "udp_client.h"

#ifdef _MSC_VER
    #define snprintf _snprintf_s
#endif // _MSC_VER

UdpTestClient::UdpTestClient()
    : m_running(false)
    , m_xactor(nullptr)
    , m_thread_vector()
    , m_user_data_map()
    , m_user_data_mutex()
{

}

UdpTestClient::~UdpTestClient()
{
    exit();
}

bool UdpTestClient::init(const char * peer_ip, unsigned short peer_port, std::size_t thread_count, std::size_t connection_count)
{
    exit();

    do
    {
        m_running = true;

        if (!init_network())
        {
            std::cout << "udp test client init failure while network init failed" << std::endl;
            break;
        }

        m_xactor = create_udp_xactor();
        if (nullptr == m_xactor)
        {
            std::cout << "udp test client init failure while udp xactor create failed" << std::endl;
            break;
        }

        if (!m_xactor->init(this, thread_count))
        {
            std::cout << "udp test client init failure while udp xactor init failed" << std::endl;
            break;
        }

        for (std::size_t connection_index = 0; connection_index < connection_count; ++connection_index)
        {
            if (!m_xactor->connect(peer_ip, peer_port, connection_index))
            {
                std::cout << "udp test client init failure while udp xactor connect failed" << std::endl;
                break;
            }
        }

        if (m_user_data_map.empty())
        {
            break;
        }

        std::cout << "udp test client init success" << std::endl;

        return (true);

    } while (false);

    exit();

    return (false);
}

void UdpTestClient::exit()
{
    if (m_running)
    {
        m_running = false;

        destroy_udp_xactor(m_xactor);
        m_xactor = nullptr;

        for (std::vector<std::thread>::iterator iter = m_thread_vector.begin(); m_thread_vector.end() != iter; ++iter)
        {
            if (iter->joinable())
            {
                iter->join();
            }
        }
        m_thread_vector.clear();

        m_user_data_map.clear();

        exit_network();
    }
}

void UdpTestClient::on_accept(socket_t sockfd)
{
    std::lock_guard<std::mutex> locker(m_user_data_mutex);
    std::cout << "invalid connection" << std::endl;
}

void UdpTestClient::on_connect(socket_t sockfd, uint64_t user_data)
{
    std::lock_guard<std::mutex> locker(m_user_data_mutex);
    session_data_t & session_data = m_user_data_map[sockfd];
    session_data.user_data = user_data + 1;
    std::cout << "connection [" << session_data.user_data << "] incoming" << std::endl;
    m_thread_vector.emplace_back(std::thread(std::bind(&UdpTestClient::send_data, this, sockfd)));
}

void UdpTestClient::on_recv(socket_t sockfd, const void * data, std::size_t data_len)
{
    recv_data(sockfd, data, data_len);
}

void UdpTestClient::on_close(socket_t sockfd)
{
    std::lock_guard<std::mutex> locker(m_user_data_mutex);
    session_data_t & session_data = m_user_data_map[sockfd];
    std::cout << "connection [" << session_data.user_data << "] outgoing" << std::endl;
    session_data.user_data = 0;
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
            std::cout << "session (" << session_id << ") " << (inbound ? "recv" : "send") << " speed: " << speed << " count: " << speed_data.valid << "/" << speed_data.total << std::endl;
        }
    }
}

bool UdpTestClient::send_data(socket_t sockfd)
{
    session_data_t * session_data = nullptr;
    {
        std::lock_guard<std::mutex> locker(m_user_data_mutex);
        session_data = &m_user_data_map[sockfd];
    }

    if (nullptr == session_data)
    {
        return (false);
    }

    char data[1400] = { 0x0 };
    std::size_t data_len = sizeof(data);
    while (m_running && 0 != session_data->user_data)
    {
        if (!m_xactor->send(sockfd, data, data_len))
        {
            continue;
        }

        session_data->send_speed.total += 1;
        session_data->send_speed.valid += 1;

        calc_speed(session_data->user_data, session_data->send_speed, false, data_len, m_user_data_mutex);
    }

    {
        std::lock_guard<std::mutex> locker(m_user_data_mutex);
        std::cout << "session (" << session_data->user_data << ") " << "send" << " count: " << session_data->send_speed.valid << "/" << session_data->send_speed.total << std::endl;
        m_user_data_map.erase(sockfd);
    }

    return (true);
}

bool UdpTestClient::recv_data(socket_t sockfd, const void * data, std::size_t data_len)
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

    session_data->recv_speed.total += 1;
    session_data->recv_speed.valid += 1;

    calc_speed(session_data->user_data, session_data->recv_speed, true, data_len, m_user_data_mutex);

    return (true);
}
