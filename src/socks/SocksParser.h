#pragma once
#include "../common/public.h"
#include "../common/Socket.h"
#include <iostream>
#include <map>
#include <string>

typedef std::map<std::string,std::string> DNS_MAP;

using namespace Socket;

enum CMDTYPE 
{
	SOCKS_CONNECT = 0x01,
	SOCKS_BIND,
	SOCKS_UDP
};


typedef struct
{
	int  socket;
	int  usocket;
	sockaddr_in caddr;//客户端udp的通信地址ip+port (ip无用)
	sockaddr_in saddr;
	in_addr  ipaddr;
	unsigned short c_port;
	unsigned short sq;//代理服务器端口?

	CMDTYPE type;
	int slocal;
	int sremote;
	LPVOID lpParameter;
}SERVICE_INFO,*PSERVICE_INFO;

typedef struct
{
	int  socket;//tcp socket
	int  usocket;//udp socket
	sockaddr_in caddr;
    sockaddr_in ccaddr;//非代理程序的ip和端口
	sockaddr_in saddr;//UDP穿透应答 : 代理服务器分配的随机端口
	in_addr  ipaddr;
	unsigned short s_port;//代理服务器TCP端口
	unsigned short sq;//代理服务器分配的随机端口

    unsigned short c_port;//本地端口：用于接收1680的数据  not use
    
	CMDTYPE type;
	int slocal;
	int sremote;
	LPVOID lpParameter;
}CLIENT_INFO,*PCLIENT_INFO;

class SocksParser
{
	DECLARE_SINGLETON(SocksParser)
private:
	static int m_socket;

	CriticalSection m_csDns;
public:
	static DNS_MAP m_dns;

public:
	bool Auth(int s,char* username,char* password,bool NeedAuth);
	static bool UDPResponse(SERVICE_INFO& svc);
    
	bool TCPResponse( SERVICE_INFO& svc );
	bool GetRequest( SERVICE_INFO& svc );

};