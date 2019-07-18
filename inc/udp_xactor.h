/********************************************************
 * Description : udp xactor
 * Author      : yanrk
 * Email       : yanrkchina@163.com
 * Version     : 2.0
 * History     :
 * Copyright(C): 2019-2020
 ********************************************************/

#ifndef UDP_XACTOR_H
#define UDP_XACTOR_H


#include <string>

#ifdef _MSC_VER
    #define UDP_XACTOR_CDECL            __cdecl
    #define UDP_XACTOR_STDCALL          __stdcall
    #ifdef EXPORT_UDP_XACTOR_DLL
        #define UDP_XACTOR_API          __declspec(dllexport)
    #else
        #ifdef USE_UDP_XACTOR_DLL
            #define UDP_XACTOR_API      __declspec(dllimport)
        #else
            #define UDP_XACTOR_API
        #endif // USE_UDP_XACTOR_DLL
    #endif // EXPORT_UDP_XACTOR_DLL
#else
    #define UDP_XACTOR_CDECL
    #define UDP_XACTOR_STDCALL
    #define UDP_XACTOR_API
#endif // _MSC_VER

namespace UdpXactor { // namespace UdpXactor begin

struct UDP_XACTOR_API FecConfiguration
{
    bool            enable_fec;
    uint32_t        fec_encode_max_block_size;     // 1200
    double          fec_encode_recovery_rate;      // 0.05
    bool            fec_encode_force_recovery;     // true
    uint32_t        fec_decode_expire_millisecond; // 15
};

class UDP_XACTOR_API UdpConnectionBase
{
public:
    virtual ~UdpConnectionBase() = 0;

public:
    virtual void set_user_data(void * user_data) = 0;
    virtual void * get_user_data() = 0;

public:
    virtual void get_host_address(std::string & ip, unsigned short & port) = 0;
    virtual void get_peer_address(std::string & ip, unsigned short & port) = 0;
};

class UDP_XACTOR_API UdpServiceBase
{
public:
    virtual ~UdpServiceBase() = 0;

public:
    virtual void on_accept(UdpConnectionBase * connection) = 0;
    virtual void on_connect(UdpConnectionBase * connection, void * user_data) = 0;
    virtual void on_recv(UdpConnectionBase * connection, const void * data, std::size_t size) = 0;
    virtual void on_close(UdpConnectionBase * connection) = 0;
};

class UdpManagerImpl;

class UDP_XACTOR_API UdpManager
{
public:
    UdpManager();
    ~UdpManager();

public:
    UdpManager(const UdpManager &) = delete;
    UdpManager & operator = (const UdpManager &) = delete;

public:
    bool init(UdpServiceBase * udp_service, const FecConfiguration * fec, std::size_t thread_count = 1, const char * host_ip = "0.0.0.0", unsigned short host_port = 0, bool reuse_addr = true, bool reuse_port = true);
    void exit();

public:
    bool connect(const char * peer_ip, unsigned short peer_port, void * user_data, const char * host_ip = "0.0.0.0", unsigned short host_port = 0, bool reuse_addr = true, bool reuse_port = true);
    bool send(UdpConnectionBase * connection, const void * data, std::size_t size);
    bool close(UdpConnectionBase * connection);

private:
    UdpManagerImpl                                * m_manager_impl;
};

} // namespace UdpXactor end


#endif // UDP_XACTOR_H
