﻿#include "stdafx.h"
#include "SocksMgr.h"

CSocksMgr::CSocksMgr():
    m_pwd("cs"),
    m_user("cs"),
    m_rIp("127.0.0.1"),
    m_rPort(8000),
    m_NeedAuth(FALSE)
{
}

CSocksMgr::~CSocksMgr()
{

}

DWORD WINAPI CSocksMgr::TCP_S2C(void* lpParameter)
{
    SERVICE_INFO* pSvcInfo = (SERVICE_INFO*)lpParameter;
    char buffer[1024*4] = {0};

    while (TRUE)
    {
        int nCount = recv(pSvcInfo->sremote,buffer,1024*4,0);
        if (nCount == SOCKET_ERROR)
        {
            debugLog(_T("recv Error! %d"),WSAGetLastError());
            break;
        }
        bool bRet = Socket::SendBuf(pSvcInfo->slocal,buffer,nCount);

        if (!bRet)
        {
            debugLog(_T("send Error! %d"),WSAGetLastError());
            break;
            break;
        }
    }

    Socket::Close(pSvcInfo->sremote);
    Socket::Close(pSvcInfo->slocal);

    return 0;
}

DWORD WINAPI CSocksMgr::TCP_C2S(void* lpParameter)
{
    SERVICE_INFO* pSvcInfo = (SERVICE_INFO*)lpParameter;
    char buffer[1024*4] = {0};

    while (TRUE)
    {
        int nCount = recv(pSvcInfo->slocal,buffer,1024*4,0);
        if (nCount == SOCKET_ERROR)
        {
            debugLog(_T("recv Error! %d"),WSAGetLastError());
            break;
        }

        bool bRet = Socket::SendBuf(pSvcInfo->sremote,buffer,nCount);

        if(!bRet)
        {
            debugLog(_T("send Error! %d"),WSAGetLastError());
            break;
        }
    }

    Socket::Close(pSvcInfo->sremote);
    Socket::Close(pSvcInfo->slocal);
    return 0;
}

DWORD WINAPI CSocksMgr::UDPTunnel( LPVOID lpParameter )
{
    return CSocksMgr::GetInstanceRef().UDPTunnelProc(lpParameter);
}

DWORD WINAPI CSocksMgr::UDPTunnelProc( LPVOID lpParameter )
{
    SERVICE_INFO* pSvc = (SERVICE_INFO*)lpParameter;

    //Thread t1 , t2;
    printf("==>%s\n", __func__);
    //t1.Start(LPTHREAD_START_ROUTINE fnRoutine, LPVOID lpParameter)
    //t1.Start((LPTHREAD_START_ROUTINE)TCP_C2S,pSvc);
    //t2.Start((LPTHREAD_START_ROUTINE)TCP_S2C, pSvc);
    while (TRUE)
    {
        bool bRet = SocksParser::UDPResponse(*pSvc);
        if (!bRet)
        {
            debugLog(_T("proxy Error! %d"),WSAGetLastError());
            break;
        }
    }
    
    //t1.WaitForEnd();
    //t2.WaitForEnd();


    debugLog(_T("Tunnel thread finish!"));
    if (pSvc)
    {
        free(pSvc);
    }

    return TRUE;
}

DWORD WINAPI CSocksMgr::TCPTunnel( LPVOID lpParameter )
{
    return CSocksMgr::GetInstanceRef().TCPTunnelProc(lpParameter);
}

DWORD WINAPI CSocksMgr::TCPTunnelProc( LPVOID lpParameter )
{
    SERVICE_INFO* pSvc = (SERVICE_INFO*)lpParameter;

    Thread t1 , t2;

    t1.Start((LPTHREAD_START_ROUTINE)TCP_C2S,pSvc);
    t2.Start((LPTHREAD_START_ROUTINE)TCP_S2C, pSvc);

    t1.WaitForEnd();
    t2.WaitForEnd();


    debugLog(_T("Tunnel thread finish!"));
    if (pSvc)
    {
        free(pSvc);
    }

    return TRUE;
}

bool CSocksMgr::Proxy( int s,LPSTR user , LPSTR pwd )
{
    SERVICE_INFO *pSvc = new SERVICE_INFO;
    pSvc->socket = s;

    bool ret = FALSE;

    do 
    {
        ret = 1;//SocksParser::GetInstanceRef().Auth(s ,user,pwd,m_NeedAuth);

        if ( ! ret )
            break;

        ret = SocksParser::GetInstanceRef().GetRequest(*pSvc);

        if ( ! ret )
            break;

        if (pSvc->type == SOCKS_UDP)
        {
            ret = SocksParser::GetInstanceRef().TCPResponse(*pSvc);
            printf("==>%sline[%d]\n", __func__, __LINE__);
            //joy open
            //开个线程专门转发
            //ret = SocksParser::GetInstanceRef().UDPResponse(*pSvc);
            if ( ! ret )
            {
                printf("server -- tcp -- client fail!\n");
                break;
            }
            
            Thread t;
            
            printf("==>%sline[%d]\n", __func__, __LINE__);
            ret = t.Start((LPTHREAD_START_ROUTINE)UDPTunnel, pSvc);
        }
        else
        {
            ret = SocksParser::GetInstanceRef().TCPResponse(*pSvc);

            if ( ! ret )
                break;

            Thread t;

            //进入纯转发模式
            ret = t.Start((LPTHREAD_START_ROUTINE)TCPTunnel,pSvc);
        }

    } while (FALSE);

    if ( !ret )
    {
        debugLog(_T("Proxy Error!"));
        delete pSvc;
    }

    return ret;

}

DWORD WINAPI CSocksMgr::Forward(void* lpParameter)
{
    return CSocksMgr::GetInstanceRef().ForwardProc(lpParameter);
}

DWORD WINAPI CSocksMgr::ForwardProc(void* lpParameter)
{
    int s = (int)(lpParameter);

    bool ret = Proxy(s,(LPSTR)m_user.c_str(),(LPSTR)m_pwd.c_str());

    if ( !ret )
        Socket::Close(s);

    return 0;
}

DWORD WINAPI CSocksMgr::Redirect( LPVOID lpParameter )
{
    return CSocksMgr::GetInstanceRef().RedirectProc(lpParameter);
}

DWORD WINAPI CSocksMgr::RedirectProc( LPVOID lpParameter )
{
    PROXY_CONFIG* config = (PROXY_CONFIG*)lpParameter;

    int slocal = Socket::Create();
    int sremote = Socket::Create();

    bool ret = FALSE;

    do 
    {
        ret = Socket::Connect(sremote,m_rIp.c_str(),m_rPort);

        if ( !ret )
            break;

        ret = Socket::Connect(slocal,config->ip,config->port);

        if ( !ret )
            break;

        Socket::SendBuf(slocal,(char*)config,sizeof(PROXY_CONFIG));

        SERVICE_INFO *pSvc = new SERVICE_INFO;
        pSvc->slocal = slocal;
        pSvc->sremote = sremote;

        Thread t;

        //进入纯转发模式
        ret = t.Start((LPTHREAD_START_ROUTINE)TCPTunnel,pSvc);

    } while (FALSE);

    if (config)
    {
        free(config);
    }

    return ret;
}

DWORD WINAPI CSocksMgr::Reverse(void* lpParameter)
{
    return CSocksMgr::GetInstanceRef().ReverseProc(lpParameter);
}

DWORD WINAPI CSocksMgr::ReverseProc(void* lpParameter)
{
    PROXY_CONFIG* config = (PROXY_CONFIG*)lpParameter;
    int s = Socket::Create();

    bool ret = FALSE;

    do 
    {
        ret = Socket::Connect(s,config->ip,config->port);

        if ( !ret )
            break;

        Socket::SendBuf(s,(char*)config,sizeof(PROXY_CONFIG));

        ret = Proxy(s,config->user,config->pwd);

    } while (FALSE);

    if ( !ret )
    {
        Socket::Close(s);
    }

    if (config)
    {
        free(config);
    }

    return ret;
}


bool CSocksMgr::Begin( LPCSTR ip1, int port1,LPCSTR ip2,int port2)
{
    m_rIp = ip2;
    m_rPort = port2;

    int s = Socket::Create();

    if (s == SOCKET_ERROR)
        return 0;

    infoLog(_T("[Svr] Connecting %s:%d"),a2t(ip1),port1);

    if(!Socket::Connect(s,ip1,port1))
    {
        errorLog(_T("[Svr] Connect Faild!"));
        return FALSE;
    }

    infoLog(_T("[Svr] Connect Success!"));


    bool ret = FALSE;
    PROXY_CONFIG* proxy = new PROXY_CONFIG;

    do
    {
        ret = RecvBuf(s,(char*)proxy,sizeof(PROXY_CONFIG));

        if ( !ret )
            break;

        strncpy(proxy->ip,ip1,20);
        strncpy(proxy->user,m_user.c_str(),20);
        strncpy(proxy->pwd,m_pwd.c_str(),20);

        Thread t;

        proxy->lpParameter = (uint32_t)this;
        t.Start((LPTHREAD_START_ROUTINE)Redirect,proxy);

        proxy = new PROXY_CONFIG;

    }while(TRUE);

    errorLog(_T("Disconnect!"));

    return ret;
}

bool CSocksMgr::Begin( LPCSTR ip, int port )
{
    int s = Socket::Create();

    if (s == SOCKET_ERROR)
        return 0;

    infoLog(_T("[Svr] Connecting %s:%d"),a2t(ip),port);

    if(!Socket::Connect(s,ip,port))
    {
        errorLog(_T("[Svr] Connect Faild!"));
        return FALSE;
    }

    infoLog(_T("[Svr] Connect Success!"));

    bool ret = FALSE;
    PROXY_CONFIG* proxy = new PROXY_CONFIG;

    do
    {
        ret = RecvBuf(s,(char*)proxy,sizeof(PROXY_CONFIG));

        if ( !ret )
            break;

        strncpy(proxy->ip,ip,20);
        strncpy(proxy->user,m_user.c_str(),20);
        strncpy(proxy->pwd,m_pwd.c_str(),20);

        Thread t;

        proxy->lpParameter = (uint32_t)this;
        t.Start((LPTHREAD_START_ROUTINE)Reverse,proxy);

        proxy = new PROXY_CONFIG;

    }while(TRUE);

    errorLog(_T("Disconnect!"));

    return ret;
}

bool CSocksMgr::Begin( int port )
{
    int s = Socket::Create();



    if (s == SOCKET_ERROR)
        return 0;

    bool ret = FALSE;
    do 
    {
        
        if ( ! Socket::Listen(s ,port))
        {
            errorLog(_T("Bind %d faild!"),port);
            break;
        }

        infoLog(_T("[Svr] Listening %d"),port);

        sockaddr_in raddr;

        while (TRUE)
        {
            int rs = Socket::Accept(s,(sockaddr*)&raddr);

            if (rs == SOCKET_ERROR)
            {
                errorLog(_T("Accept faild!"),port);
                ret = FALSE;
                break;
            }

            infoLog(_T("[Svr] Accept : %s"),a2t(inet_ntoa(raddr.sin_addr)));
            
            Thread t;

            t.Start((LPTHREAD_START_ROUTINE)Forward,(void*)rs);
        }


    } while (FALSE);

    errorLog(_T("Disconnect!"));

    return ret;
}

void CSocksMgr::Close()
{
}

void CSocksMgr::Wait()
{
}

void CSocksMgr::SetAuth( LPCTSTR user,LPCTSTR pwd )
{
    m_user = t2a(user);
    m_pwd = t2a(pwd);
    m_NeedAuth = TRUE;
}
