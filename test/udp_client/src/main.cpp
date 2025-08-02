/********************************************************
 * Description : udp client main
 * Author      : yanrk
 * Email       : yanrkchina@163.com
 * Version     : 1.0
 * History     :
 * Copyright(C): 2025
 ********************************************************/

#include <string>
#include <iostream>
#include "udp_client.h"

int main(int, char * [])
{
    UdpTestClient client;

    if (!client.init("127.0.0.1", 54321, 1, 1, true))
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

    client.exit();

    return 0;
}
