#include "stdafx.h"
#include "SocksParser.h"

int SocksParser::m_socket = 1024;


DNS_MAP SocksParser::m_dns = DNS_MAP();

SocksParser::SocksParser()
{
    //m_dns.insert(std::make_pair("a", "ad")); 
}
SocksParser::~SocksParser()
{

}

bool SocksParser::GetRequest( SERVICE_INFO& svc )
{
    /* cli --> srv  request*/
    /* ATYP(0x1:ipv4 0x3:DOMAINNAME 0x4: ipv6) */
	/*
	 +----+-----+-------+------+----------+----------+
	  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.gListenSocket |
	  +----+-----+-------+------+----------+----------+
	  | 1  |  1  | X'00' |  1   | Variable |    2     |
	  +----+-----+-------+------+----------+----------+
	*/
	char buffer[1024]={0x5, 0x03, 0xf, 0x1,};
	sockaddr_in svr = {0};
#if 1 // 使用TCP接收UDP穿透请求 
	if(!RecvBuf(svc.socket,buffer,10))
		return FALSE;
#else

#endif
	switch (buffer[1])
	{
		case 0x01:
			svc.type = SOCKS_CONNECT;
			break;
		case 0x02:
			svc.type = SOCKS_BIND;
			break;
		case 0x03://UDP 穿透请求
			svc.type = SOCKS_UDP;
			break;
	}
		
	//需要连接一个IP
	if (buffer[3] == 0x01)
	{
#if 1 //joy
        //buffer[4] = 192;
        //buffer[5] = 168;
        //buffer[6] = 27;
        //buffer[7] = 101;
        
        //buffer[8] = 0x6; 
        //buffer[9] = 0x90;
#else
#endif
		infoLog(_T("[Svr] THE DESTINATION IP : %d.%d.%d.%d "),\
			buffer[4]&0xff,buffer[5]&0xff,buffer[6]&0xff,buffer[7]&0xff) ;

		infoLog(_T("[Svr] THE DESTINATION PORT : %d"),((int)buffer[8])*256 + (unsigned char)buffer[9]);

		svr.sin_family = AF_INET;
		svr.sin_port = htons(((int)buffer[8])*256 + (unsigned char)buffer[9]);
		svr.sin_addr.s_addr =
			MAKELONG(MAKEWORD((buffer[4]&0xff),(buffer[5]&0xff)),
			MAKEWORD((buffer[6]&0xff),(buffer[7]&0xff))) ;

	}
		//需要连接一个域名
	else if (buffer[3] == 0x03)
	{
		int i = 0;
		int NameSize = buffer[4]&0xff;

		//接收域名
		if (NameSize >= 6)
			RecvBuf(svc.socket,&buffer[4]+6,NameSize-5);

		char szName[100];

		for (i = 0;i < NameSize;++i)
			szName[i] = buffer[i+5];

		szName[i] = 0;
		infoLog(_T("[Svr] The disire DomainName : %s"),a2t(szName));

		svr.sin_family = AF_INET;


		//请求DNS
		svr.sin_addr = GetName(szName);

		//如果请求DNS失败
		if (svr.sin_addr.s_addr == 0)
		{
			errorLog(_T("QUERY DNS Error"));
			return FALSE;
		}

		i += 5;
		//接收端口号
		infoLog(_T("[Svr] The disire IP :%s"),a2t(inet_ntoa(svr.sin_addr)));

		RecvBuf(svc.socket,&buffer[i],2);

		infoLog(_T("[Svr] The destination port : %d"),(buffer[i]&0xff)*256 + (unsigned char)buffer[i+1]);

		svr.sin_port = htons((buffer[i]&0xff)*256 + (unsigned char)buffer[i+1]);
	}

	//设置sockaddr_in
	svc.saddr = svr;
	svc.slocal = svc.socket;

	if (svc.type == SOCKS_UDP)
	{
        //udp 穿透请求
        printf("udp穿透 req\n");
		svc.caddr = svr;

		sockaddr_in addr;
		socklen_t size = sizeof(addr);

		svc.usocket = Socket::Create(FALSE);

		getpeername(svc.socket,(sockaddr*)&addr,&size);
		svc.caddr.sin_addr = addr.sin_addr;
	}
	else if (svc.type == SOCKS_CONNECT)
	{
		svc.sremote = Create();
	}
	else if (svc.type == SOCKS_BIND)
	{
		svc.slocal = Create();

		if (!Socket::Bind(svc.slocal,svc.sq,svc.saddr))
		{
			return FALSE;
		}
	}
	return TRUE;
}

bool SocksParser::TCPResponse( SERVICE_INFO& svc )
{
		/*
		  +----+-----+-------+------+----------+----------+
		|VER | REP |  RSV  | ATYP | BND.ADDR | BND.gListenSocket |
		+----+-----+-------+------+----------+----------+
		| 1  |  1  | X'00' |  1   | Variable |    2     |
		+----+-----+-------+------+----------+----------+
		*/
		char buffer[1024];
		int nAddrSize = sizeof(sockaddr);

		buffer[0] = 0x05;
		buffer[1] = 0x00;
		buffer[2] = 0x00;
		buffer[3] = 0x01;
		GetHostIP(buffer+4);
		m_socket++;
		svc.sq = m_socket;
		infoLog(_T("[Svr] proxy dispatch port :%d"), svc.sq);
		buffer[8] = svc.sq/256;
		buffer[9] = svc.sq%256;

		SendBuf(svc.socket,buffer,10);

		bool ret = FALSE;

		do 
		{
			if (svc.type == SOCKS_CONNECT)
			{
				if(!Socket::Connect(svc.sremote,svc.saddr))
				{
					Socket::Close(svc.sremote);
					break;
				}
			}
			if (svc.type == SOCKS_BIND)
			{
				svc.sremote = Socket::Accept(svc.slocal,(sockaddr*)&svc.caddr);
				if (svc.sremote == SOCKET_ERROR)
				{
					Socket::Close(svc.slocal);
					break;
				}
				break;
			}
            if (svc.type == SOCKS_UDP)
            {
#if 1 //joy
                //svc.sq = 8085;
                infoLog(_T("[Svr] SVR THE PROXY BND IP : %d.%d.%d.%d "),\
                buffer[4]&0xff,buffer[5]&0xff,buffer[6]&0xff,buffer[7]&0xff) ;
                if (!Socket::Bind(svc.usocket, svc.sq, svc.saddr))
                {
                    printf("server usocket[%d] binding udp port[%d] fail!\n", svc.usocket, svc.sq);
                    return FALSE;
                }
#endif
            }

			ret = TRUE;

		} while (FALSE);

		return ret;
}

bool SocksParser::UDPResponse( SERVICE_INFO& svc )
{
	/*
	+----+------+------+----------+----------+----------+
	|RSV | FRAG | ATYP | DST.ADDR | DST.gListenSocket |   DATA   |
	+----+------+------+----------+----------+----------+
	| 2  |  1   |  1   | Variable |    2     | Variable |
	+----+------+------+----------+----------+----------+
	*/
	int i = 0;
	sockaddr_in desireAddr,SourceAddr;

	desireAddr.sin_family = AF_INET;

	socklen_t nSockSize = sizeof(SourceAddr);
	int nStartPos = 0;
#if 1 //joy
    char buffer[10+1024*4]={0};
#else
	char buffer[1024*4];
#endif
#if 0
	int nCount = recvfrom(svc.usocket, &buffer[10], 1024*4,0,(sockaddr*)&SourceAddr,&nSockSize);
#else
    int nCount = recvfrom(svc.usocket,buffer,1024*4,0,(sockaddr*)&SourceAddr,&nSockSize);
#endif
    printf("[Svr] ==>%s recvfrom \n", __func__);
	if (nCount == SOCKET_ERROR)
	{
		debugLog(_T("[SVR] Recvfrom() Error!"));
		return FALSE;
	}
#if 0 //joy
	buffer[10+nCount] = 0;
#else
    buffer[nCount] = 0;
#endif
	//通过端口判断来源
    printf("[Svr] src port[%d] caddr.port[%d]\n", ntohs(SourceAddr.sin_port), ntohs(svc.caddr.sin_port));
	if ( SourceAddr.sin_port == svc.caddr.sin_port )
	{
		int nAType = 0x1;//joy buffer[3];
		infoLog(_T("[Svr] The address type : %d " ),nAType);

		if (nAType == 0x01)
		{
#if 0 //joy
            buffer[4] = 192;
            buffer[5] = 168;
            buffer[6] = 27;
            buffer[7] = 101;
            buffer[8] = 0x6; 
            buffer[9] = 0x90;
#endif
            infoLog(_T("[Svr] The disire socket : %d.%d.%d.%d"),buffer[4]&0xff,buffer[5]&0xff,buffer[6]&0xff , buffer[7]&0xff);

			desireAddr.sin_addr.s_addr =MAKELONG(MAKEWORD((buffer[4]&0xff),(buffer[5]&0xff)),
				MAKEWORD((buffer[6]&0xff),(buffer[7]&0xff)));;

			infoLog(_T("[Svr] The disire socket : %d"),(buffer[8]&0xff)*256 + (unsigned char)buffer[9]);
			desireAddr.sin_port  = htons((buffer[8]&0xff)*256 + (unsigned char)buffer[9]);
			nStartPos = 10;
		}
		else if (nAType == 0x03)
		{
			int nDomainNameSize = buffer[4]&0xff;
			char szDomainName[100];

			for (i = 0;i < nDomainNameSize;++i)
				szDomainName[i] = buffer[i+5];

			szDomainName[i] = 0;

			infoLog(_T("[Svr] The disire doaminname : %s"),szDomainName);

			desireAddr.sin_addr = GetName(szDomainName);

// 			m_csDns.Enter();
// 			{
// 				m_dns[std::string(inet_ntoa(desireAddr.sin_addr))] = std::string(szDomainName);
// 			}
// 			m_csDns.Leave();
			
			i += 5;

			infoLog(_T("[Svr] the disire socket : %d"),(buffer[i]&0xff)*256 + (unsigned char)buffer[i+1]);

			desireAddr.sin_port = htons((buffer[i]&0xff)*256 + (unsigned char)buffer[i+1]);
			nStartPos = i + 2;
		}
		else if (nAType == 0x04)
		{
			//ipv6 not implement:)
		}
        #if 0  //joy
        #else
		nCount -= nStartPos;
        #endif
		sendto(svc.usocket,buffer+nStartPos,nCount,0,(sockaddr*)&desireAddr,sizeof(desireAddr));
	}
	else
	{
		//封装这个消息
		infoLog(_T("[Svr] GOT MESSAGE FROM : %s :%d"),inet_ntoa(SourceAddr.sin_addr),ntohs(SourceAddr.sin_port));

		char reply[1024*4];
		if (m_dns.find(std::string(inet_ntoa(SourceAddr.sin_addr))) == m_dns.end())
		{
			reply[0] = reply[1] = reply[2] = 0;
			reply[3] = 0x01;//IP V4 address: X'01'
			memcpy(reply+4,(void*)&SourceAddr.sin_addr.s_addr,4);

			reply[8] = ntohs(SourceAddr.sin_port)/256;
			reply[9] = ntohs(SourceAddr.sin_port)%256;
			for (i = 0;i < nCount;++i)
				reply[10+i] = buffer[i];
			sendto(svc.usocket,reply,10+nCount,0,(sockaddr*)&svc.caddr,sizeof(sockaddr));
		}
		else
		{
			reply[0] = reply[1] = reply[2] = 0;
			reply[3] = 0x03;// DOMAINNAME: X'03'
			std::string strDomainName = m_dns[std::string(inet_ntoa(SourceAddr.sin_addr))];
			infoLog(_T("[Svr] The domain name : %s"), strDomainName.c_str() );

			reply[4] = strDomainName.size();
			for (UINT i = 0;i < strDomainName.size();++i)
				reply[5+i] = strDomainName[i];

			sendto(svc.usocket,reply,5+strDomainName.size(),0,(sockaddr*)&svc.caddr,sizeof(svc.caddr));
			nCount =	sendto(svc.usocket,buffer,nCount,0,(sockaddr*)&svc.caddr,sizeof(svc.caddr));
			infoLog(_T("[Svr] actually reply : %d") , nCount);
		}
	}
	return TRUE;
}

bool SocksParser::Auth(int s,char* username,char* password,bool NeedAuth)
{
	/*
	  +----+----------+----------+
	  |VER | NMETHODS | METHODS  |
	  +----+----------+----------+
	  | 1  |    1     | 1 to 255 |
	  +----+----------+----------+
	*/
	int i = 0;
	char buffer[1024];

	RecvBuf(s,buffer,2);

	int type = buffer[1];

	RecvBuf(s,buffer,type);

	for (i = 0;i < type;++i)
		if (buffer[i] == 0x02)
			break;
	/*
	 +----+-----------------+
	 |VER | METHOD CHOSSED  |
	 +----+-----------------+
	 | 1  |    1 to 255     |
	 +----+-----------------+
	*/
	char replay[2];
	replay[0] = 0x05;

	//需要身份认证
	if (NeedAuth)
	{
		//没有密码
		if (i == type)
		{
			replay[1] = 0xff;
		}
		else
		{
			replay[1] = 0x02;
		}
	}
	//不需要
	else
	{
		replay[1] = 0x00;
	}
	SendBuf(s,replay,2);

	//只支持密码通信
	if (replay[1] == 0xff) 
		return FALSE;

	if (replay[1] == 0x00)
		return TRUE;
	/*
	+----+------+----------+------+----------+
	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	+----+------+----------+------+----------+
	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	+----+------+----------+------+----------+
	*/
	RecvBuf(s,buffer,2);
	int nLen = buffer[1];

	RecvBuf(s,buffer,nLen);

	buffer[nLen] = 0;
	char user[256];
	strncpy(user,buffer,256);

	RecvBuf(s,buffer,1);
	int nPLen = buffer[0];
	RecvBuf(s,buffer,nPLen);

	buffer[nPLen] = 0;
	char pwd[256];

	strncpy(pwd,buffer,256);
	/*
	+----+--------+
	|VER | STATUS |
	+----+--------+
	| 1  |   1    |
	+----+--------+
	*/
	replay[0] = 0x05;

	if (!strcmp(user,username) && !strcmp(pwd,password))
		replay[1] = 0x00;
	else
		replay[1] = 0x01;

	SendBuf(s,replay,2);
	return replay[1] == 0x00;
}
