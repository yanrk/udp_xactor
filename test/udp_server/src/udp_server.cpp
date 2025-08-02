/********************************************************
 * Description : udp server
 * Author      : yanrk
 * Email       : yanrkchina@163.com
 * Version     : 1.0
 * History     :
 * Copyright(C): 2025
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
    , m_fec()
    , m_manager()
    , m_send_back(false)
    , m_session_index(0)
    , m_user_data_map()
    , m_user_data_mutex()
{
    memset(&m_fec, 0x0, sizeof(m_fec));
}

UdpTestServer::~UdpTestServer()
{
    exit();
}

bool UdpTestServer::init(const char * ip, uint16_t port, uint16_t thread_count, bool use_fec, bool send_back, bool use_listen)
{
    exit();

    do
    {
        m_running = true;

        m_send_back = send_back;

        m_session_index = 0;

        if (use_fec)
        {
            m_fec.enable_fec = true;
            m_fec.fec_encode_max_block_size = 1200;
            m_fec.fec_encode_recovery_rate = 0.05;
            m_fec.fec_encode_force_recovery = true;
            m_fec.fec_decode_expire_millisecond = 15;
        }

        if (use_listen)
        {
            if (!m_manager.init(this, use_fec ? &m_fec : nullptr, thread_count))
            {
                std::cout << "udp test server init failure while udp manager init failed" << std::endl;
                break;
            }

            if (!m_manager.listen(ip, port, nullptr, false, true, true))
            {
                std::cout << "udp test server init failure while udp manager listen failed" << std::endl;
                break;
            }
        }
        else
        {
            if (!m_manager.init(this, use_fec ? &m_fec : nullptr, thread_count))
            {
                std::cout << "udp test server init failure while udp manager init failed" << std::endl;
                break;
            }

            if (!m_manager.accept(ip, port, nullptr, true, true))
            {
                std::cout << "udp test server init failure while udp manager accept failed" << std::endl;
                break;
            }
        }

        std::cout << "udp test server init success" << std::endl;

        return true;

    } while (false);

    exit();

    return false;
}

void UdpTestServer::exit()
{
    if (m_running)
    {
        m_running = false;

        m_manager.exit();

        m_user_data_map.clear();
    }
}

void UdpTestServer::on_listen(UdpXactor::UdpConnectionBase * connection, void * user_data)
{
    std::lock_guard<std::mutex> locker(m_user_data_mutex);
    session_data_t & session_data = m_user_data_map[connection];
    session_data.user_data = ++m_session_index;
    std::cout << "connection [" << session_data.user_data << "] incoming from listen" << std::endl;
}

void UdpTestServer::on_accept(UdpXactor::UdpConnectionBase * connection, void * user_data)
{
    std::lock_guard<std::mutex> locker(m_user_data_mutex);
    session_data_t & session_data = m_user_data_map[connection];
    session_data.user_data = ++m_session_index;
    std::cout << "connection [" << session_data.user_data << "] incoming from accept" << std::endl;
}

void UdpTestServer::on_connect(UdpXactor::UdpConnectionBase * connection, void * user_data)
{
    std::lock_guard<std::mutex> locker(m_user_data_mutex);
    std::cout << "invalid connection" << std::endl;
}

void UdpTestServer::on_recv(UdpXactor::UdpConnectionBase * connection, const void * data, std::size_t size)
{
    recv_data(connection, data, size);
}

void UdpTestServer::on_close(UdpXactor::UdpConnectionBase * connection)
{
    std::lock_guard<std::mutex> locker(m_user_data_mutex);
    session_data_t & session_data = m_user_data_map[connection];
    std::cout << "session (" << session_data.user_data << ") " << "recv" << " count: " << session_data.recv_speed.count << std::endl;
    std::cout << "connection [" << session_data.user_data << "] outgoing" << std::endl;
    m_user_data_map.erase(connection);
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

bool UdpTestServer::send_data(UdpXactor::UdpConnectionBase * connection, const void * data, std::size_t size)
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

    if (!m_manager.send(connection, data, size))
    {
        return false;
    }

    session_data->send_speed.count += 1;

    calc_speed(session_data->user_data, session_data->send_speed, false, size, m_user_data_mutex);

    return true;
}

bool UdpTestServer::recv_data(UdpXactor::UdpConnectionBase * connection, const void * data, std::size_t size)
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

    if (nullptr != data && 0 != size)
    {
        session_data->recv_speed.count += 1;
    }

    calc_speed(session_data->user_data, session_data->recv_speed, true, size, m_user_data_mutex);

    if (m_send_back)
    {
        send_data(connection, data, size);
    }

    return true;
}
