#include "httpauth.h"
 
// Constants are the integer part of the sines of integers (in radians) * 2^32.
const uint32_t k[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
 
// r specifies the per-round shift amounts
const uint32_t r[] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
	};
 
 
// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
 
 

 
void to_bytes(uint32_t val, uint8_t *bytes)
{
	bytes[0] = (uint8_t) val;
	bytes[1] = (uint8_t) (val >> 8);
	bytes[2] = (uint8_t) (val >> 16);
	bytes[3] = (uint8_t) (val >> 24);
}
 
uint32_t to_int32(const uint8_t *bytes)
{
	    return (uint32_t) bytes[0]
			| ((uint32_t) bytes[1] << 8)
			| ((uint32_t) bytes[2] << 16)
			| ((uint32_t) bytes[3] << 24);
}
 
void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {
	// These vars will contain the hash
	uint32_t h0, h1, h2, h3;
		 
	// Message (to prepare)
	uint8_t *msg = NULL;
			 
	size_t new_len, offset;
	uint32_t w[16];
	uint32_t a, b, c, d, i, f, g, temp;
						 
	// Initialize variables - simple count in nibbles:
	h0 = 0x67452301;
	h1 = 0xefcdab89;
	h2 = 0x98badcfe;
	h3 = 0x10325476;
										 
	//Pre-processing:
	//append "1" bit to message    
	//append "0" bits until message length in bits � 448 (mod 512)
	//append length mod (2^64) to message
										 
	for (new_len = initial_len + 1; new_len % (512/8) != 448/8; new_len++)
		;

	msg = (uint8_t*)malloc(new_len + 8);
	memcpy(msg, initial_msg, initial_len);
	msg[initial_len] = 0x80; // append the "1" bit; most significant bit is "first"
	for (offset = initial_len + 1; offset < new_len; offset++)
		msg[offset] = 0; // append "0" bits
															 
	// append the len in bits at the end of the buffer.
	to_bytes(initial_len*8, msg + new_len);
	// initial_len>>29 == initial_len*8>>32, but avoids overflow.
	to_bytes(initial_len>>29, msg + new_len + 4);

	// Process the message in successive 512-bit chunks:
	//for each 512-bit chunk of message:
	for(offset=0; offset<new_len; offset += (512/8)) {
		// break chunk into sixteen 32-bit words w[j], 0 � j � 15
		for (i = 0; i < 16; i++)
			w[i] = to_int32(msg + offset + i*4);

		// Initialize hash value for this chunk:
		a = h0;
		b = h1;
		c = h2;
		d = h3;

		// Main loop:
		for(i = 0; i<64; i++) {
			if (i < 16) {
				f = (b & c) | ((~b) & d);
				g = i;
			} else if (i < 32) {
				f = (d & b) | ((~d) & c);
				g = (5*i + 1) % 16;
			} else if (i < 48) {
				f = b ^ c ^ d;
				g = (3*i + 5) % 16;          
			} else {
				f = c ^ (b | (~d));
				g = (7*i) % 16;
			}

			temp = d;
			d = c;
			c = b;
			b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
			a = temp;
		}

		// Add this chunk's hash to result so far:
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
	}

	// cleanup
	free(msg);

	//var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
	to_bytes(h0, digest);
	to_bytes(h1, digest + 4);
	to_bytes(h2, digest + 8);
	to_bytes(h3, digest + 12);
}

void to_hex(char *in,int len,unsigned char *out)
{
	static char const hex[]="0123456789abcdef";
	unsigned i;

	memset(out,0,len*2+1);

	for(i=0;i<len;i++)
	{
		out[2*i]=hex[ (in[i] >>4)&0x0F ];
		out[2*i+1]=hex[ (in[i] & 0x0F) ];
		//printf("%d#%2.2x##%2.2x###%2.2x\n",i,in[i],out[2*i],out[2*i+1]);
	}
}

int httpauth_set_auth(httpauth_t *auth,const char* username,const char* password,const char* realm,const char* nonce,const char* nc,const char* cnonce,const char* response,const char* qop)
{
	strcpy(auth->username,username);
	strcpy(auth->password,password);
	strcpy(auth->realm,realm);
	strcpy(auth->nonce,nonce);
	strcpy(auth->nc,nc);
	strcpy(auth->cnonce,cnonce);
	strcpy(auth->response,response);	
	strcpy(auth->qop,qop);
	return 0;
}

int httpauth_get_response(httpauth_t *auth,char *cmd,char *url)
{
	uint8_t strH1[512],strH2[512];
	uint8_t md5_h1[33],md5_h2[33];
	uint8_t result[16],result2[16];
	size_t len;

	//md5(md5(<username>:<realm>:<password>):<nonce>:md5(<cmd>:<url>))
	memset(strH1,0,512);
	sprintf(strH1,"%s:%s:%s",auth->username,auth->realm,auth->password);
	len = strlen(strH1);
	md5(strH1, len, result);
	to_hex(result,16,md5_h1);
//	printf("HA1 = %s\r\n",md5_h1);
	
	memset(strH2,0,512);
	sprintf(strH2,"%s:%s",cmd,url);
	len = strlen(strH2);
	md5(strH2, len, result2);
	to_hex(result2,16,md5_h2);
//	printf("HA2 = %s\r\n",md5_h2);
	

	memset(strH1,0,512);
	sprintf(strH1,"%s:%s:%s:%s:%s:%s",md5_h1,auth->nonce,auth->nc,auth->cnonce,auth->qop,md5_h2);
//	printf("response %s\r\n",strH1);
	len = strlen(strH1);
	md5(strH1, len, result);
	to_hex(result,16,auth->response);
//	printf("response = %s\r\n",auth->response);




	return 0;
}

/**********************************************************************/
/* send a no authentication request */
/**********************************************************************/
void request(int socket_fd,httpauth_t *auth,int flag)
{
	char buf[2048];
	int pos = 0;

//    sprintf(buf, "GET /ISAPI/Streaming/channels/101/picture HTTP/1.1\r\n\r\n");
//	send(socket_fd, buf, strlen(buf), 0);
//    sprintf(buf, "Host:192.168.3.64\r\n\r\n");
//    send(socket_fd, buf, strlen(buf), 0);
//    sprintf(buf, "Connection: keep-alive\r\n\r\n");
//	send(socket_fd, buf, strlen(buf), 0);
//    if(1 == flag)
//	{
//    sprintf(buf, "Authorization: Digest username=\"admin\", realm=\"DS-2CD2520F\", nonce=\"%s\", uri=\"/ISAPI/Streaming/channels/101/picture\", response=\"%s\", qop=auth, nc=00000001, cnonce=\"%s\"\r\n\r\n",auth->nonce,auth->response,auth->cnonce);
//	send(socket_fd, buf, strlen(buf), 0);
//	}
//    sprintf(buf, "Upgrade-Insecure-Requests: 1\r\n\r\n");
//	send(socket_fd, buf, strlen(buf), 0);
//    sprintf(buf, "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 SE 2.X MetaSr 1.0\r\n\r\n");
//	send(socket_fd, buf, strlen(buf), 0);
//    sprintf(buf, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\r\n");
//	send(socket_fd, buf, strlen(buf), 0);
//    sprintf(buf, "Accept-Encoding: gzip, deflate, sdch\r\n\r\n");
//	send(socket_fd, buf, strlen(buf), 0);
//	sprintf(buf, "Accept-Language: zh-CN,zh;q=0.8\r\n\r\n");
//	send(socket_fd, buf, strlen(buf), 0);

	
	pos = sprintf(&buf[pos], "GET /ISAPI/Streaming/channels/101/picture HTTP/1.1\r\n");
	pos += sprintf(&buf[pos], "Host:192.168.3.64\r\n");
	pos += sprintf(&buf[pos], "Connection: keep-alive\r\n");
	pos += sprintf(&buf[pos], "Cache-Control: max-age=0\r\n");
    if(1 == flag)
	{
    	pos += sprintf(&buf[pos], "Authorization: Digest username=\"admin\", realm=\"DS-2CD2520F\", nonce=\"%s\", uri=\"/ISAPI/Streaming/channels/101/picture\", response=\"%s\", qop=auth, nc=00000001, cnonce=\"%s\"\r\n",auth->nonce,auth->response,auth->cnonce);
	}
    pos += sprintf(&buf[pos], "Upgrade-Insecure-Requests: 1\r\n");
    pos += sprintf(&buf[pos], "User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 SE 2.X MetaSr 1.0\r\n");
    pos += sprintf(&buf[pos], "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n");
    pos += sprintf(&buf[pos], "Accept-Encoding: gzip, deflate, sdch\r\n");
    pos += sprintf(&buf[pos], "Accept-Language: zh-CN,zh;q=0.8\r\n");
    pos += sprintf(&buf[pos], "\r\n");
    printf("%s\r\n",buf);
    send(socket_fd, buf, strlen(buf), 0);
	
}

/**********************************************************************
int prase_response(char * response_buf )
**********************************************************************/

int prase_response(char * response_buf ,httpauth_t *auth)
{
	char * begin=NULL , *end=NULL;
	if(strstr(response_buf,"401")!=NULL)
	{	
		printf("the servers return 401 \r\n");
		if(strstr(response_buf,"401")!=NULL)
		{
			begin = strstr(response_buf,"\"");
			end   =	strstr(begin+1,"\"");
			memcpy(auth->qop,begin+1,end-begin-1);
			
			begin = strstr(end+1,"\"");
			end   =	strstr(begin+1,"\"");
			memcpy(auth->realm,begin+1,end-begin-1);
			
			begin = strstr(end+1,"\"");
			end   =	strstr(begin+1,"\"");
			memcpy(auth->nonce,begin+1,end-begin-1);
            memcpy(auth->cnonce,auth->nonce,16);
		}
//		printf("qop:%s\r\n"  ,auth->qop);
//		printf("realm:%s\r\n",auth->realm);
//		printf("nonce:%s\r\n",auth->nonce);
	}
	else if(strstr(response_buf,"200")!=NULL)
		printf("the servers return 200 ok\r\n");
		
	return 0 ;
	
}


