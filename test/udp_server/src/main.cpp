/********************************************************
 * Description : udp server main
 * Author      : yanrk
 * Email       : yanrkchina@163.com
 * Version     : 1.0
 * History     :
 * Copyright(C): 2025
 ********************************************************/

#include <string>
#include <iostream>
#include "udp_server.h"

int main(int, char * [])
{
    UdpTestServer server;
    if (!server.init("0.0.0.0", 54321, 1, true, true, true))
    {
        return 1;
    }

    while (true)
    {
        std::string command;
        std::cin.clear();
        std::cin.sync();
        std::cin >> command;
        if ("exit" == command)
        {
            break;
        }
    }

    server.exit();

    return 0;
}
