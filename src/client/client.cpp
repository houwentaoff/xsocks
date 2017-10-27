#include "stdafx.h"
#include <map>
#include <string>
#include "Tunnel.h"
#include "th3rd/dns.h"
#include "socks/SocksMgr.h"
#include "client.h"

//using namespace std;
unsigned short SocksClint::random_port=8000;    

SocksClint::SocksClint()
{

}
bool SocksClint::Auth(int s,char* username,char* password,bool NeedAuth)
{
    bool ret = true;
    return ret;
}
bool SocksClint::Begin( LPCSTR ip, int tcp_port, int udp_port = random_port)
{
    bool ret = false;
    int s = Socket::Create();

    if (s == SOCKET_ERROR)
        return 0;

    infoLog(_T("[Cli] Connecting %s:%d"),a2t(ip), tcp_port);

    if(!Socket::Connect(s, ip , tcp_port))
    {
        errorLog(_T("[Cli] Connect Faild!"));
        return FALSE;
    }

    infoLog(_T("[Cli] Connect Success!"));

    CLIENT_INFO *cli = new CLIENT_INFO();
    cli->socket = s;
    do
    {
        //ret = RecvBuf(s,(char*)proxy,sizeof(PROXY_CONFIG));
        ret = UDPRequest(*cli);//tcp
        if ( !ret )
            break;        
        ret = GetResponse(*cli);
        if ( !ret )
            break;
        //strncpy(proxy->ip,ip,20);
        //strncpy(proxy->user,m_user.c_str(),20);
        //strncpy(proxy->pwd,m_pwd.c_str(),20);
        //udp
        cli->usocket = Socket::Create(FALSE);
        if (!Socket::Bind(cli->usocket, udp_port/*cli.c_port*/, cli->caddr))
        {
            errorLog(_T("[Cli] Bind random port err!"));
            return FALSE;
        }
        printf("[CLI] tcp resp :svr udp port[%d]\n", ntohs(cli->saddr.sin_port));
        infoLog(_T("[Cli] Binging Success! port : %d!"), random_port);

        Thread t;

        t.Start((LPTHREAD_START_ROUTINE)UDPTunnel, cli);
    }while(FALSE);

    return ret;
}

//udp穿透的请求 以TCP交互：向服务器发穿透请求
bool SocksClint::UDPRequest(CLIENT_INFO& cli)
{
    /* ATYP(0x1:ipv4 0x3:DOMAINNAME 0x4: ipv6) */
    /*
     +----+-----+-------+------+----------+----------+
      |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.gListenSocket |
      +----+-----+-------+------+----------+----------+
      | 1  |  1  | X'00' |  1   | Variable |    2     |
      +----+-----+-------+------+----------+----------+
    */
    bool ret = false;
    char buffer[1024];
    
    //cli.sq = 0;
    buffer[0] = 0x05; // socks5
    buffer[1] = 0x03; //udp associate
    buffer[2] = 0x00;
    buffer[3] = 0x01;  //ipv4
    if (buffer[3] == 0x1)
    {
        buffer[4] = 127;
        buffer[5] = 0;
        buffer[6] = 0;
        buffer[7] = 1;

        buffer[8] = (char)((random_port&0xff00)>>8); //1681
        buffer[9] = (char)random_port&0xff;
        ret = true;
    }
    SendBuf(cli.socket, buffer, 10);
    return ret;
}

//TCP穿透的请求 以TCP交互
bool SocksClint::TCPRequest( CLIENT_INFO& cli )
{
    bool ret = false;
    

    
    return ret;
}
DWORD WINAPI SocksClint::UDPTunnel( LPVOID lpParameter )
{
    CLIENT_INFO* pCli = (CLIENT_INFO*)lpParameter;

    while (TRUE)
    {
        bool bRet = SocksClint::UDPDataRequest(*pCli);
        if (!bRet)
        {
            debugLog(_T("proxy Error! %d"),WSAGetLastError());
            break;
        }
    }

    debugLog(_T("Cli UDP Data thread finish!"));
    if (pCli)
    {
        ;//free(pSvc);
    }

    return TRUE;

}
//UDP数据加头转发
bool SocksClint::UDPDataRequest(CLIENT_INFO& cli)
{
    bool ret = true;
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
    char buffer[10+1024*4]={0};

#if 1
    int nCount = recvfrom(cli.usocket, &buffer[10], 1024*4, 0, (sockaddr*)&SourceAddr, &nSockSize);
#else
    int nCount = recvfrom(svc.usocket,buffer,1024*4,0,(sockaddr*)&SourceAddr,&nSockSize);
#endif
    if (nCount == SOCKET_ERROR)
    {
        debugLog(_T("Recvfrom() Error!"));
        return FALSE;
    }
#if 1 //joy
    buffer[10+nCount] = 0;
#else
    buffer[nCount] = 0;
#endif

    buffer[0] = buffer[1] = 0x0;
    buffer[2] = 0;//not use
    buffer[3] = 0x1;//ipv4
    printf("CLI sourceaddr.port[%d] cli.saddr.port[%d]\n", ntohs(SourceAddr.sin_port), ntohs(cli.saddr.sin_port));
    //通过端口判断来源
    if ( SourceAddr.sin_port != cli.saddr.sin_port )//up
    {
        int nAType = buffer[3];
        infoLog(_T("[Cli] The address type : %d " ),nAType);

        if (nAType == 0x01)
        {
            //外部参数
            buffer[4] = 10;//112;//192;
            buffer[5] = 2;//74;//168;
            buffer[6] = 15;//72;//27;
            buffer[7] = 136;//127;//101;
            buffer[8] = 0x6;//0x6; 
            buffer[9] = 0xa4;//0x90;
            cli.ccaddr = SourceAddr;
#if 0
            infoLog(_T("The disire socket : %d.%d.%d.%d"),buffer[4]&0xff,buffer[5]&0xff,buffer[6]&0xff , buffer[7]&0xff);

            desireAddr.sin_addr.s_addr =MAKELONG(MAKEWORD((buffer[4]&0xff),(buffer[5]&0xff)),
                MAKEWORD((buffer[6]&0xff),(buffer[7]&0xff)));;

            infoLog(_T("The disire socket : %d"),(buffer[8]&0xff)*256 + (unsigned char)buffer[9]);
            desireAddr.sin_port  = htons((buffer[8]&0xff)*256 + (unsigned char)buffer[9]);
#endif
            nStartPos = 10;
        }
        else if (nAType == 0x03)
        {
#if 0
            int nDomainNameSize = buffer[4]&0xff;
            char szDomainName[100];

            for (i = 0;i < nDomainNameSize;++i)
                szDomainName[i] = buffer[i+5];

            szDomainName[i] = 0;

            infoLog(_T("The disire doaminname : %s"),szDomainName);

            desireAddr.sin_addr = GetName(szDomainName);

//          m_csDns.Enter();
//          {
//              m_dns[std::string(inet_ntoa(desireAddr.sin_addr))] = std::string(szDomainName);
//          }
//          m_csDns.Leave();
            
            i += 5;

            infoLog(_T("the disire socket : %d"),(buffer[i]&0xff)*256 + (unsigned char)buffer[i+1]);

            desireAddr.sin_port = htons((buffer[i]&0xff)*256 + (unsigned char)buffer[i+1]);
            nStartPos = i + 2;
#endif
        }
        else if (nAType == 0x04)
        {
            //ipv6 not implement:)
        }
    #if 1  //joy
    #else
        nCount -= nStartPos;
    #endif
        //加密
        sendto(cli.usocket, buffer, nCount+10, 0, (sockaddr*)&cli.saddr,sizeof(sockaddr));
    }
    else//down
    {
        //解包这个消息
        infoLog(_T("[Cli] GOT MESSAGE FROM : %s :%d"),inet_ntoa(SourceAddr.sin_addr),ntohs(SourceAddr.sin_port));

        //char reply[1024*4];
        if (1/*m_dns.find(std::string(inet_ntoa(SourceAddr.sin_addr))) == m_dns.end()*/)
        {
#if 0            
            reply[0] = reply[1] = reply[2] = 0;
            reply[3] = 0x01;//IP V4 address: X'01'
            memcpy(reply+4,(void*)&SourceAddr.sin_addr.s_addr,4);

            reply[8] = ntohs(SourceAddr.sin_port)/256;
            reply[9] = ntohs(SourceAddr.sin_port)%256;
            for (i = 0;i < nCount;++i)
                reply[10+i] = buffer[i];
#endif
            printf("cli down : port[%d]\n", (unsigned short)buffer[10+8]*256 + (unsigned short)buffer[10+9]);
            //解密
            sendto(cli.usocket, &buffer[20], nCount, 0, (sockaddr*)&cli.ccaddr, sizeof(sockaddr));
        }
        else
        {
#if 0
            reply[0] = reply[1] = reply[2] = 0;
            reply[3] = 0x03;// DOMAINNAME: X'03'
            std::string strDomainName = m_dns[std::string(inet_ntoa(SourceAddr.sin_addr))];
            infoLog(_T("The domain name : %s"), strDomainName.c_str() );

            reply[4] = strDomainName.size();
            for (UINT i = 0;i < strDomainName.size();++i)
                reply[5+i] = strDomainName[i];

            sendto(svc.usocket,reply,5+strDomainName.size(),0,(sockaddr*)&svc.caddr,sizeof(svc.caddr));
            nCount =    sendto(svc.usocket,buffer,nCount,0,(sockaddr*)&svc.caddr,sizeof(svc.caddr));
            infoLog(_T("actually reply : %d") , nCount);
#endif 
        }
    }

    return ret;
}

bool SocksClint::TCPDataRequest(CLIENT_INFO& cli)
{
    bool ret = true;
    
    return ret;
}
//获取代理服务器回应:包含随机端口地址
bool SocksClint::GetResponse( CLIENT_INFO& cli )
{
    bool ret = true;
    char buffer[1024]={0x0};
    sockaddr_in svr = {0};
    if(!RecvBuf(cli.socket, buffer, 10))
        return FALSE;
    
    if (buffer[3] == 0x01)//ipv4
    {

        infoLog(_T("[Cli] THE PROXY BND IP : %d.%d.%d.%d "),\
            buffer[4]&0xff,buffer[5]&0xff,buffer[6]&0xff,buffer[7]&0xff) ;

        infoLog(_T("[CLI] THE PROXY BND PORT : %d"),((int)buffer[8])*256 + (unsigned char)buffer[9]);

        svr.sin_family = AF_INET;
        svr.sin_port = htons(((int)buffer[8])*256 + (unsigned char)buffer[9]);
        svr.sin_addr.s_addr =
            MAKELONG(MAKEWORD((buffer[4]&0xff),(buffer[5]&0xff)),
            MAKEWORD((buffer[6]&0xff),(buffer[7]&0xff))) ;
        cli.saddr = svr;
        printf("[CLI] tcp resp :svr udp port[%d]\n", ntohs(cli.saddr.sin_port));
    }
    

    return ret;
}


