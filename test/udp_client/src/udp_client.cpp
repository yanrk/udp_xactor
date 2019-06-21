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
#include <list>
#include <string>
#include <chrono>
#include <iostream>
#include <functional>
#include "udp_client.h"

#ifdef _MSC_VER
    #define snprintf _snprintf_s
#endif // _MSC_VER

UdpTestClient::UdpTestClient()
    : m_running(false)
    , m_use_fec(false)
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

bool UdpTestClient::init(const char * peer_ip, unsigned short peer_port, std::size_t thread_count, std::size_t connection_count, bool use_fec)
{
    exit();

    do
    {
        m_running = true;

        m_use_fec = use_fec;

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

        if (!m_xactor->init(this, use_fec, thread_count))
        {
            std::cout << "udp test client init failure while udp xactor init failed" << std::endl;
            break;
        }

        for (std::size_t connection_index = 0; connection_index < connection_count; ++connection_index)
        {
            if (!m_xactor->connect(peer_ip, peer_port, reinterpret_cast<void *>(connection_index)))
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

void UdpTestClient::on_accept(IUdpConnection * connection)
{
    std::lock_guard<std::mutex> locker(m_user_data_mutex);
    std::cout << "invalid connection" << std::endl;
}

void UdpTestClient::on_connect(IUdpConnection * connection, void * user_data)
{
    std::lock_guard<std::mutex> locker(m_user_data_mutex);
    session_data_t & session_data = m_user_data_map[connection];
    session_data.user_data = reinterpret_cast<uint64_t>(user_data) + 1;
    std::cout << "connection [" << connection << "] incoming" << std::endl;
    m_thread_vector.emplace_back(std::thread(std::bind(&UdpTestClient::send_data, this, connection)));
}

void UdpTestClient::on_recv(IUdpConnection * connection, const void * data, std::size_t size)
{
    recv_data(connection, data, size);
}

void UdpTestClient::on_close(IUdpConnection * connection)
{
    std::lock_guard<std::mutex> locker(m_user_data_mutex);
    session_data_t & session_data = m_user_data_map[connection];
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
            std::cout << "session (" << session_id << ") " << (inbound ? "recv" : "send") << " speed: " << speed << " count: " << speed_data.count << std::endl;
        }
    }
}

bool UdpTestClient::send_data(IUdpConnection * connection)
{
    session_data_t * session_data = nullptr;
    {
        std::lock_guard<std::mutex> locker(m_user_data_mutex);
        session_data = &m_user_data_map[connection];
    }

    if (nullptr == session_data)
    {
        return (false);
    }

    char data[1400] = { 0x0 };
    std::size_t data_len = sizeof(data);
    while (m_running && 0 != session_data->user_data)
    {
        if (!m_xactor->send(connection, data, data_len))
        {
            continue;
        }

        session_data->send_speed.count += 1;

        calc_speed(session_data->user_data, session_data->send_speed, false, data_len, m_user_data_mutex);
    }

    {
        std::lock_guard<std::mutex> locker(m_user_data_mutex);
        std::cout << "session (" << session_data->user_data << ") " << "send" << " count: " << session_data->send_speed.count << std::endl;
        m_user_data_map.erase(connection);
    }

    return (true);
}

bool UdpTestClient::recv_data(IUdpConnection * connection, const void * data, std::size_t size)
{
    session_data_t * session_data = nullptr;
    {
    //  std::lock_guard<std::mutex> locker(m_user_data_mutex);
        session_data = &m_user_data_map[connection];
    }

    if (nullptr == session_data)
    {
        return (false);
    }

    session_data->recv_speed.count += 1;

    calc_speed(session_data->user_data, session_data->recv_speed, true, size, m_user_data_mutex);

    return (true);
}
