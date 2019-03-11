#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include "httpauth.h"

char * url ="/ISAPI/Streaming/channels/101/picture" ;
char * cmd = "GET";

const char * username_t ="admin";
const char * passworld_t ="byjt1234";
const char * realm_t ="DS-2CD2520F";
const char * nonce_t ="4d6a46444d7a5a464e3045364e5449355a546c695932553d";
const char * nc_t ="00000001";
const char * cnonce_t ="8887920ea7e5c1c8";
const char * response_t ="5a9aa58fb654e667ad9d8e8adaa336df";
const char * qop_t ="auth";

FILE *fp = NULL;


int main(int argc,char * argv[])
{
    int sd, ret;
	char rcv_buf[1024*1204];
    struct sockaddr_in ser_sockaddr;
    int cnt = 0;
    char *begin=NULL;
	httpauth_t auth;

	if(argc!=3)
	{
		printf("您输入的参数不够(服务器的IP、端口号)\r\n");
		return -1;
	}
 while(1)
 {
    //返回套接字描述符
    sd = socket(AF_INET, SOCK_STREAM, 0); //创建socket连接 选择IPV4的TCP协议数据包
    if(sd==-1)
	{
		printf("TCP套接字创建失败\r\n");
	}
	
   //设置sockaddr_in结构体中相关参数
    ser_sockaddr.sin_family =  AF_INET;          //地址族 IPV4
	//    ser_sockaddr.sin_port   =  htons(atoi(argv[2]));  //设置为要连接的服务器的端口号(short数据转化为网络数据)
	//    ser_sockaddr.sin_addr.s_addr  = inet_addr(argv[1]); //设置服务器的IP地址(字符串转化为整形)

    ser_sockaddr.sin_port   =  htons(80);  //设置为要连接的服务器的端口号(short数据转化为网络数据)
    ser_sockaddr.sin_addr.s_addr  = inet_addr("192.168.3.64"); //设置服务器的IP地址(字符串转化为整形)

    ret = connect(sd, (struct sockaddr *)&ser_sockaddr, sizeof(ser_sockaddr));//连接服务器
    if(ret==-1)
	{
		printf("连接服务器失败\r\n");
		return -1;
	}
	printf("连接服务器成功\r\n");
	
	
	struct timeval timeout = {10, 0};
	//    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));//set recv timeout
	
    	if(cnt == 0){
    		httpauth_set_auth(&auth,username_t,passworld_t,realm_t,nonce_t,nc_t,cnonce_t,response_t,qop_t);
			request(sd,&auth,0);
			recv(sd,rcv_buf,1024,0);
			printf("%s",rcv_buf);
			prase_response(rcv_buf,&auth);
    	}
    	else{
    		int rs = 1;
    		int buflen = 0;
            int rev_pos = 0;
            int len;
            int jpeg_len;
			httpauth_get_response(&auth,cmd,url);
			memset(rcv_buf,0,1024);
			request(sd,&auth,1);
			sleep(1);

			len = sizeof(rcv_buf);
			while(rs)
			{
			    buflen = recv(sd, &rcv_buf[rev_pos],len - rev_pos , 0);
                printf("buflen is %d \r\n",buflen);
			    if(buflen < 0)
			    {
			        // 由于是非阻塞的模式,所以当buflen为EAGAIN时,表示当前缓冲区已无数据可读
			        // 在这里就当作是该次事件已处理
			        if(errno == EINTR)
			            continue;
			        else
			            break;
			    }
			    else if(buflen == 0)
			    {
			        // 这里表示对端的socket已正常关闭.
                    
			    	 begin = strstr(rcv_buf,"Content-Length:");
			    	 jpeg_len = atoi(begin+15);
                     begin = strstr(rcv_buf,"\r\n\r\n");
                     
                     fp = fopen("./pic.JPEG", "w+");
                     fwrite(begin+4,jpeg_len,1, fp);
                      
                
                    return 0;
			    }

			    if(buflen != sizeof(rcv_buf))
			        rs = 1;
			    else
			        rs = 0;// 需要再次读取

                printf("rs is %d \r\n",rs);
                rev_pos += buflen;
			}
            return 0;
    	}

    close(sd);
    cnt ++;
    if(cnt >= 2) cnt = 0;
 }
    return 0;
}
