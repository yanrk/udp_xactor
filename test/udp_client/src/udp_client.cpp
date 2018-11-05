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
    , m_need_codec(false)
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

bool UdpTestClient::init(const char * peer_ip, unsigned short peer_port, std::size_t thread_count, std::size_t connection_count, bool need_codec)
{
    exit();

    do
    {
        m_running = true;

        m_need_codec = need_codec;

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
    session_data.need_codec = m_need_codec;
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
            std::cout << "session (" << session_id << ") " << (inbound ? "recv" : "send") << " speed: " << speed << std::endl;
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

    if (session_data->need_codec)
    {
        srand(static_cast<uint32_t>(time(0)));

        std::list<std::vector<uint8_t>> src_data_list;
        for (std::size_t i = 0; i < 240; ++i)
        {
            uint8_t buffer[1400] = { 0x0 };
            for (std::size_t j = 0; j < sizeof(buffer); ++j)
            {
                buffer[j] = static_cast<uint8_t>(rand() % 256);
            }
            src_data_list.push_back(std::vector<uint8_t>(buffer, buffer + 1001 + rand() % 400));
        }

        while (m_running && 0 != session_data->user_data)
        {
            std::list<std::vector<uint8_t>> tmp_data_list;

            send_frame_t & send_frame = session_data->send_frame;
            if (!cm256_encode(send_frame.frame_index, send_frame.frame_filter, tmp_data_list, src_data_list, 0.1, 0, true))
            {
                return (false);
            }

            while (tmp_data_list.size() > src_data_list.size() + 10)
            {
                tmp_data_list.pop_front();
            }

            std::list<std::vector<uint8_t>>::const_iterator iter = tmp_data_list.begin();
            while (m_running && 0 != session_data->user_data && tmp_data_list.end() != iter)
            {
                const std::vector<uint8_t> & data = *iter++;

                if (!m_xactor->send(sockfd, &data[0], data.size()))
                {
                    continue;
                }

                calc_speed(session_data->user_data, session_data->send_speed, false, data.size(), m_user_data_mutex);
            }
        }
    }
    else
    {
        char data[1400] = { 0x0 };
        std::size_t data_len = sizeof(data);
        while (m_running && 0 != session_data->user_data)
        {
            if (!m_xactor->send(sockfd, data, data_len))
            {
                continue;
            }

            calc_speed(session_data->user_data, session_data->send_speed, false, data_len, m_user_data_mutex);
        }
    }

    {
        std::lock_guard<std::mutex> locker(m_user_data_mutex);
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

    calc_speed(session_data->user_data, session_data->recv_speed, true, data_len, m_user_data_mutex);

    return (true);
}
