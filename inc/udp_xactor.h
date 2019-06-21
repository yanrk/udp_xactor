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


#ifdef _MSC_VER
    #define UDP_XACTOR_CDECL             __cdecl
    #define UDP_XACTOR_STDCALL           __stdcall
    #ifdef EXPORT_UDP_XACTOR_DLL
        #define UDP_XACTOR_TYPE          __declspec(dllexport)
    #else
        #ifdef USE_UDP_XACTOR_DLL
            #define UDP_XACTOR_TYPE      __declspec(dllimport)
        #else
            #define UDP_XACTOR_TYPE
        #endif // USE_UDP_XACTOR_DLL
    #endif // EXPORT_UDP_XACTOR_DLL
#else
    #define UDP_XACTOR_CDECL
    #define UDP_XACTOR_STDCALL
    #define UDP_XACTOR_TYPE
#endif // _MSC_VER

#define UDP_CXX_API(return_type) extern UDP_XACTOR_TYPE return_type UDP_XACTOR_CDECL

#include <cstdint>

#ifdef _MSC_VER
    #ifdef _WIN64
        typedef uint64_t    socket_t;
    #else
        typedef uint32_t    socket_t;
    #endif // _WIN64
#else
    typedef int32_t         socket_t;
#endif // _MSC_VER

class UDP_XACTOR_TYPE IUdpConnection
{
public:
    virtual ~IUdpConnection() = 0;

public:
    virtual void set_user_data(void * user_data) = 0;
    virtual void * get_user_data() = 0;
};

class UDP_XACTOR_TYPE IUdpSink
{
public:
    virtual ~IUdpSink() = 0;

public:
    virtual void on_accept(IUdpConnection * connection) = 0;
    virtual void on_connect(IUdpConnection * connection, void * user_data) = 0;
    virtual void on_recv(IUdpConnection * connection, const void * data, std::size_t size) = 0;
    virtual void on_close(IUdpConnection * connection) = 0;
};

class UDP_XACTOR_TYPE IUdpXactor
{
public:
    virtual ~IUdpXactor() = 0;

public:
    virtual bool init(IUdpSink * udp_sink, bool use_fec, std::size_t thread_count = 1, const char * host_ip = "0.0.0.0", unsigned short host_port = 0, bool reuse_addr = true, bool reuse_port = true) = 0;
    virtual void exit() = 0;

public:
    virtual bool connect(const char * peer_ip, unsigned short peer_port, void * user_data, const char * host_ip = "0.0.0.0", unsigned short host_port = 0, bool reuse_addr = true, bool reuse_port = true) = 0;
    virtual bool send(IUdpConnection * connection, const void * data, std::size_t size) = 0;
    virtual bool close(IUdpConnection * connection) = 0;
};

UDP_CXX_API(bool) init_network();
UDP_CXX_API(bool) exit_network();

UDP_CXX_API(IUdpXactor *) create_udp_xactor();
UDP_CXX_API(void) destroy_udp_xactor(IUdpXactor *);


#endif // UDP_XACTOR_H
