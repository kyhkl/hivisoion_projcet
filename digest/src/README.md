#http协议之digest(摘要)认证
用于RTSP、SIP中的注册/呼叫认证

##digest的算法：
A1 = username:realm:password
A2 = mthod:uri

HA1 = MD5(A1)
如果 qop 值为“auth”或未指定，那么 HA2 为
HA2 = MD5(A2)=MD5(method:uri)
如果 qop 值为“auth-int”，那么 HA2 为
HA2 = MD5(A2)=MD5(method:uri:MD5(entityBody))

如果 qop 值为“auth”或“auth-int”，那么如下计算 response：
response = MD5(HA1:nonce:nc:cnonce:qop:HA2)

如果 qop 未指定，那么如下计算 response：
response = MD5(HA1:nonce:HA2)

##功能实现
###MD5
void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest);
###digest认证
int httpauth_set_user_pwd(httpauth_t *auth,char* username,char* password);
int httpauth_set_realm_nonce(httpauth_t *auth,char* realm,char* nonce);
int httpauth_get_response(httpauth_t *auth,char *cmd,char *url,char *response);
###结构
struct httpauth_t

##test
###httpauth_test.c
参考[https://blog.csdn.net/yuanbinquan/article/details/56851328](https://blog.csdn.net/yuanbinquan/article/details/56851328 "yuanbinquan的专栏")中RTSP的验证过程与数据

	httpauth_t auth;
	httpauth_set_user_pwd(&auth,user,password);
	httpauth_set_realm_nonce(&auth,realm,nonce);
	httpauth_get_response(&auth,cmd,url,response);
