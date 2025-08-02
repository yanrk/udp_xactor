/********************************************************
 * Description : udp client
 * Author      : yanrk
 * Email       : yanrkchina@163.com
 * Version     : 1.0
 * History     :
 * Copyright(C): 2025
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
    , m_fec()
    , m_manager()
    , m_thread_vector()
    , m_user_data_map()
    , m_user_data_mutex()
{
    memset(&m_fec, 0x0, sizeof(m_fec));
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

        if (use_fec)
        {
            m_fec.enable_fec = true;
            m_fec.fec_encode_max_block_size = 1200;
            m_fec.fec_encode_recovery_rate = 0.05;
            m_fec.fec_encode_force_recovery = true;
            m_fec.fec_decode_expire_millisecond = 15;
        }

        if (!m_manager.init(this, use_fec ? &m_fec : nullptr, thread_count))
        {
            std::cout << "udp test client init failure while udp manager init failed" << std::endl;
            break;
        }

        for (std::size_t connection_index = 0; connection_index < connection_count; ++connection_index)
        {
            if (!m_manager.connect(peer_ip, peer_port, reinterpret_cast<void *>(connection_index)))
            {
                std::cout << "udp test client init failure while udp manager connect failed" << std::endl;
                break;
            }
        }

        if (m_user_data_map.empty())
        {
            break;
        }

        std::cout << "udp test client init success" << std::endl;

        return true;

    } while (false);

    exit();

    return false;
}

void UdpTestClient::exit()
{
    if (m_running)
    {
        m_running = false;

        m_manager.exit();

        for (std::vector<std::thread>::iterator iter = m_thread_vector.begin(); m_thread_vector.end() != iter; ++iter)
        {
            if (iter->joinable())
            {
                iter->join();
            }
        }
        m_thread_vector.clear();

        m_user_data_map.clear();
    }
}

void UdpTestClient::on_listen(UdpXactor::UdpConnectionBase * connection, void * user_data)
{
    std::lock_guard<std::mutex> locker(m_user_data_mutex);
    std::cout << "invalid connection" << std::endl;
}

void UdpTestClient::on_accept(UdpXactor::UdpConnectionBase * connection, void * user_data)
{
    std::lock_guard<std::mutex> locker(m_user_data_mutex);
    std::cout << "invalid connection" << std::endl;
}

void UdpTestClient::on_connect(UdpXactor::UdpConnectionBase * connection, void * user_data)
{
    std::lock_guard<std::mutex> locker(m_user_data_mutex);
    session_data_t & session_data = m_user_data_map[connection];
    session_data.user_data = reinterpret_cast<uint64_t>(user_data) + 1;
    std::cout << "connection [" << session_data.user_data << "] incoming" << std::endl;
    m_thread_vector.emplace_back(std::thread(std::bind(&UdpTestClient::send_data, this, connection)));
}

void UdpTestClient::on_recv(UdpXactor::UdpConnectionBase * connection, const void * data, std::size_t size)
{
    recv_data(connection, data, size);
}

void UdpTestClient::on_close(UdpXactor::UdpConnectionBase * connection)
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

bool UdpTestClient::send_data(UdpXactor::UdpConnectionBase * connection)
{
    session_data_t * session_data = nullptr;
    {
        std::lock_guard<std::mutex> locker(m_user_data_mutex);
        session_data = &m_user_data_map[connection];
    }

    if (nullptr == session_data)
    {
        return false;
    }

    char data[1400] = { 0x0 };
    std::size_t data_len = sizeof(data);
    while (m_running && 0 != session_data->user_data)
    {
        if (!m_manager.send(connection, data, data_len))
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

    return true;
}

bool UdpTestClient::recv_data(UdpXactor::UdpConnectionBase * connection, const void * data, std::size_t size)
{
    session_data_t * session_data = nullptr;
    {
    //  std::lock_guard<std::mutex> locker(m_user_data_mutex);
        session_data = &m_user_data_map[connection];
    }

    if (nullptr == session_data)
    {
        return false;
    }

    session_data->recv_speed.count += 1;

    calc_speed(session_data->user_data, session_data->recv_speed, true, size, m_user_data_mutex);

    return true;
}
