/********************************************************
 * Description : udp client main
 * Author      : ryan
 * Email       : ryan@rayvision.com
 * Version     : 1.0
 * History     :
 * Copyright(C): RAYVISION
 ********************************************************/

#include <string>
#include <iostream>
#include "udp_client.h"

int main(int, char * [])
{
    UdpTestClient client;

    if (!client.init("127.0.0.1", 54321, 1, 1, false))
    {
        return (1);
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

    return (0);
}
