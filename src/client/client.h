#pragma once

#ifdef LINUX
    #include <stdio.h>
    #include <stdlib.h>
    #include <error.h>
    #include <string.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>

#else
#endif
class SocksClint
{
    //DECLARE_SINGLETON(SocksClint)
    static unsigned short random_port;    
public:
    SocksClint();
    bool Auth(int s,char* username,char* password,bool NeedAuth);
    
    bool Begin( LPCSTR ip, int tcp_port, int udp_port);
    bool UDPRequest(CLIENT_INFO& cli);
    
    bool TCPRequest( CLIENT_INFO& cli );
    
    static DWORD WINAPI UDPTunnel( LPVOID lpParameter );
    static bool UDPDataRequest(CLIENT_INFO& cli);
    bool TCPDataRequest(CLIENT_INFO& cli);
    bool GetResponse( CLIENT_INFO& cli );
};

