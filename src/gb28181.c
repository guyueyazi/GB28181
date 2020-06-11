#include <ifaddrs.h>
#include <stdbool.h>
#include "public.h"
#include "osip2/osip_mt.h"
#include "eXosip2/eXosip.h"
#include "HTTPDigest.h"

#define NONCE       "1234567890123456"
#define EXPIRY      3600
#define PORT        5060
#define UAS_VERSION "Hikvision"//"SipUAv0.1"
#define PASSWD      "123456"
#define TIMEOUT     1800
#define RTP_PORT    18040
#define USER_PORT   5060

typedef struct {
    char *remote_ip;
    char *port;
} media_info_t;

typedef struct {
    struct eXosip_t *ctx;
    pthread_t tid;
    int running;
    int callid;
    char *user_id;
    char *user_ip;
    int user_port;
    int registered;
    char *server_ip;
    int regid;
    int mode;
    char *sip_id;
    char *relm;
} app_t;

enum {
    MODE_CLIENT,
    MODE_SERVER,
};

static app_t app;

void show_info()
{
    printf("--- sip id: \t%s\n", app.sip_id);
    printf("--- passwd: \t%s\n", PASSWD);
    printf("--- realm: \t%s\n", app.relm);
    printf("--- nonce: \t%s\n", NONCE);
    printf("--- expiry: \t%d\n", EXPIRY);
    printf("--- port: \t%d\n", PORT);
    printf("--- transport: \tudp\n");
    printf("--- server: \t%s\n", app.server_ip);
    printf("--- user id: \t%s\n", app.user_id);
}

const char* get_ip(void)
{
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char *host = NULL;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return NULL;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (!strcmp(ifa->ifa_name, "lo"))
            continue;
        if (family == AF_INET) {
            if ((host = (char*)malloc(NI_MAXHOST)) == NULL)
                return NULL;
            s = getnameinfo(ifa->ifa_addr,
                    (family == AF_INET) ? sizeof(struct sockaddr_in) :
                    sizeof(struct sockaddr_in6),
                    host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                return NULL;
            }
            freeifaddrs(ifaddr);
            return host;
        }
    }
    return NULL;
}


void dbg_dump_request(eXosip_event_t *evtp)
{
    char *s;
    size_t len;

    osip_message_to_str(evtp->request, &s, &len);
    printf("%s", s);
}
void dbg_dump_response(eXosip_event_t *evtp)
{
    char *s;
    size_t len;

    osip_message_to_str(evtp->response, &s, &len);
    printf("%s", s);
}

static void register_response(eXosip_event_t *evtp, int code)
{
    int ret = 0 ;
    osip_message_t * reg = NULL;

    ret = eXosip_message_build_answer (app.ctx, evtp->tid, code, &reg);
    if (!ret && reg) {
        eXosip_lock(app.ctx);
        LOGI("send register answer");
        eXosip_message_send_answer (app.ctx, evtp->tid, code, reg);
        eXosip_unlock(app.ctx);
    } else {
        LOGE("build answer error(%d)", ret);
    }
}

static void response200(eXosip_event_t *evtp)
{
    int ret = 0 ;
    osip_message_t * msg = NULL;

    ret = eXosip_message_build_answer (app.ctx, evtp->tid, 200, &msg);
    if (!ret && msg) {
        eXosip_lock(app.ctx);
        LOGI("send response answer");
        eXosip_message_send_answer (app.ctx, evtp->tid, 200, msg);
        eXosip_unlock(app.ctx);
    } else {
        LOGE("build answer error(%d)", ret);
    }
}

static void register_401unauthorized_response(eXosip_event_t *evtp)
{
    int ret = 0;
    char *dest = NULL;
    osip_message_t * reg = NULL;
    osip_www_authenticate_t * header = NULL;

    osip_www_authenticate_init(&header);
    osip_www_authenticate_set_auth_type (header, osip_strdup("Digest"));
    osip_www_authenticate_set_realm(header,osip_enquote(app.relm));
    osip_www_authenticate_set_nonce(header,osip_enquote(NONCE));
    osip_www_authenticate_to_str(header, &dest);
    ret = eXosip_message_build_answer (app.ctx, evtp->tid, 401, &reg);
    if ( ret == 0 && reg != NULL ) {
        osip_message_set_www_authenticate(reg, dest);
        osip_message_set_content_type(reg, "Application/MANSCDP+xml");
        eXosip_lock(app.ctx);
        eXosip_message_send_answer (app.ctx, evtp->tid, 401, reg);
        eXosip_unlock(app.ctx);
    }

    osip_www_authenticate_free(header);
    osip_free(dest);
}

static void auth_calc_response(char *username, char *uri, char *method, HASHHEX response)
{
    HASHHEX HA1;
    HASHHEX rresponse;

    DigestCalcHA1("REGISTER", username, app.relm, PASSWD, NONCE, NULL, HA1);
    DigestCalcResponse(HA1, NONCE, NULL, NULL, NULL, 0, method, uri, NULL, rresponse);
    memcpy(response, rresponse, HASHHEXLEN);
}

static int cmd_catalog(char* from, char* to, char *sip_id)
{
    osip_message_t *msg;
    char body[1024] = {0};
    char *s;
    size_t len;

    sprintf(body, "<?xml version=\"1.0\"?>\r\n"
                  "<Query>\r\n"
                  "<CmdType>Catalog</CmdType>\r\n"
                  "<SN>1</SN>\r\n"
                  "<DeviceID>%s</DeviceID>\r\n"
                  "</Query>\r\n", sip_id);

    eXosip_message_build_request(app.ctx, &msg, "MESSAGE", to, from, NULL);
    osip_message_set_body(msg, body, strlen(body));
    osip_message_set_content_type(msg, "Application/MANSCDP+xml");
    eXosip_message_send_request(app.ctx, msg);	

    osip_message_to_str(msg, &s, &len);
    //LOGI("send cmd catalog: \n%s", s);
}

static int uas_cmd_catalog()
{
    char from[1024] = {0};
    char to[1024] = {0};

    sprintf(from, "sip:%s@%s:%d", app.sip_id, app.server_ip, USER_PORT);
    sprintf(to, "sip:%s@%s:%d", app.user_id, app.user_ip, PORT);
    LOGI("send catalog to %s", to);
    cmd_catalog(from, to, app.user_id);
}

static int uac_cmd_catalog()
{
    char from[1024] = {0};
    char to[1024] = {0};

    sprintf(from, "sip:%s@%s:%d", app.user_id, get_ip(), USER_PORT);
    sprintf(to, "sip:%s@%s:%d", app.sip_id, app.server_ip, PORT);
    cmd_catalog(from, to, app.sip_id);
}

static int cmd_callstart()
{
	int ret = -1;
	char session_exp[1024] = { 0 };
	osip_message_t *msg = NULL;
    const char *ip = get_ip();
    char from[1024] = {0};
    char to[1024] = {0};
    char contact[1024] = {0};
    char sdp[2048] = {0};
	char head[1024] = {0};
    char *s;
    size_t len;

    LOGI("ip:%s", ip);
    sprintf(from, "sip:%s@%s:%d", app.sip_id, ip, PORT);
    sprintf(contact, "sip:%s@%s:%d", app.sip_id, ip, PORT);
    sprintf(to, "sip:%s@%s:%d", app.user_id, app.user_ip, app.user_port);
    snprintf (sdp, 2048,
            "v=0\r\n"
            "o=%s 0 0 IN IP4 %s\r\n"
            "s=Play\r\n"
            "c=IN IP4 %s\r\n"
            "t=0 0\r\n"
            "m=video %d TCP/RTP/AVP 96 98 97\r\n"
            "a=recvonly\r\n"
            "a=rtpmap:96 PS/90000\r\n"
            "a=rtpmap:98 H264/90000\r\n"
            "a=rtpmap:97 MPEG4/90000\r\n"
            "a=setup:passive\r\n"
            "a=connection:new\r\n"
            "y=0100000001\r\n"
            "f=\r\n", app.sip_id, ip, ip, RTP_PORT);
	ret = eXosip_call_build_initial_invite(app.ctx, &msg, to, from,  NULL, NULL);
	if (ret) {
		LOGE( "call build failed %s %s ret:%d", from, to, ret);
		return -1;
	}

    osip_message_set_body(msg, sdp, strlen(sdp));
	osip_message_set_content_type(msg, "application/sdp");
	snprintf(session_exp, sizeof(session_exp)-1, "%i;refresher=uac", TIMEOUT);
	osip_message_set_header(msg, "Session-Expires", session_exp);
	osip_message_set_supported(msg, "timer");
	app.callid = eXosip_call_send_initial_invite(app.ctx, msg);
    osip_message_to_str(msg, &s, &len);
    printf("%s", s);
	ret = (app.callid > 0) ? 0 : -1;
    if (ret) {
        LOGE("send invite error");
    }
	return ret;
}

int register_handle(eXosip_event_t *evtp)
{
#define SIP_STRDUP(field) if (ss_dst->field) field = osip_strdup_without_quote(ss_dst->field)
    char *method = NULL, *algorithm = NULL, *username = NULL, *realm = NULL, *nonce = NULL, *nonce_count = NULL, *uri = NULL;
    char calc_response[HASHHEXLEN];
    osip_authorization_t * ss_dst = NULL;
    osip_contact_t *contact = NULL;
    HASHHEX HA1, HA2 = "", Response;

    osip_message_get_authorization(evtp->request, 0, &ss_dst);
    if (ss_dst) {
        osip_message_get_contact (evtp->request, 0, &contact);
        if (contact && contact->url) {
            app.user_ip = strdup(contact->url->host);
            app.user_port = atoi(contact->url->port);
            LOGI("user_ip:%s", app.user_ip);
        } else {
            LOGE("get contact error");
        }
        method = evtp->request->sip_method;
        SIP_STRDUP(algorithm);
        SIP_STRDUP(username);
        SIP_STRDUP(realm);
        SIP_STRDUP(nonce);
        SIP_STRDUP(nonce_count);
        SIP_STRDUP(uri);
        strcpy(app.user_id, username);
        LOGI("method: %s", method);
        LOGI("realm: %s", realm);
        LOGI("nonce: %s", nonce);
        LOGI("nonce_count: %s", nonce_count);
        LOGI("message_gop: %s", ss_dst->message_qop);
        LOGI("username: %s", username);
        LOGI("uri: %s", uri);
        LOGI("algorithm: %s", algorithm);
        LOGI("cnonce:%s", ss_dst->cnonce);
        DigestCalcHA1(algorithm, username, realm, PASSWD, nonce, nonce_count, HA1);
        DigestCalcResponse(HA1, nonce, nonce_count, ss_dst->cnonce, ss_dst->message_qop, 0, method, uri, HA2, Response);
        auth_calc_response(username, uri, method, calc_response);
        if (!memcmp(calc_response, Response, HASHHEXLEN)) {
            register_response(evtp, 200);
            app.registered = 1;
            LOGI("register_success");

        } else {
            register_response(evtp, 401);
            LOGI("register_failed");
        }
        osip_free(algorithm);
        osip_free(username);
        osip_free(realm);
        osip_free(nonce);
        osip_free(nonce_count);
        osip_free(uri);
    } else {
        LOGI("register 401_unauthorized");
        register_401unauthorized_response(evtp);
    }

    return 0;
}

void *media_thread(void *arg)
{
    int listenfd = 0, connfd = 0, ret, c;
    struct sockaddr_in serv_addr, client;
    char buf[1025];
    FILE *fp = fopen("./gb28181.ps", "w");
    const char *ip = get_ip();
    char *client_ip;
    int client_port;

    if (!fp) {
        LOGE("open file ./gb28181.ps error");
        goto exit;
    }
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ip);
    serv_addr.sin_port = htons(RTP_PORT);
    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    listen(listenfd, 10);
    LOGI("listen on %s:%d", ip, RTP_PORT);
    c = sizeof(struct sockaddr_in);
    connfd = accept(listenfd, (struct sockaddr *)&client, (socklen_t*)&c);
    client_ip = inet_ntoa(client.sin_addr);
    client_port = ntohs(client.sin_port);
    LOGI("got connection from %s:%d", client_ip, client_port);

    for (;;) {
        ret = read(connfd, buf, sizeof(buf));
        if (ret < 0) {
            LOGE("read error, %s", strerror(errno));
            goto exit;
        }
        //LOGI("size:%d", ret);
        fwrite(buf, ret, 1, fp);
        fflush(fp);
    }

exit:
    return NULL;
}

int invite_ack_handle(eXosip_event_t *evtp)
{
    int code, i;
    char setup[64];
    osip_message_t* ack;
    sdp_message_t *sdp_msg;
    sdp_connection_t *connection;
    sdp_media_t * video_sdp;
    media_info_t media;
    pthread_t tid;

    code = osip_message_get_status_code(evtp->response);		                    
    eXosip_call_build_ack(app.ctx, evtp->did, &ack);  
    eXosip_call_send_ack(app.ctx, evtp->did, ack); 
    sdp_msg = eXosip_get_remote_sdp(app.ctx, evtp->did);
    if (!sdp_msg)
        goto err;
    connection = eXosip_get_video_connection(sdp_msg);
    if (!connection)
        goto err;
    video_sdp = eXosip_get_video_media(sdp_msg);
    if (!video_sdp) 
        goto err;
    printf("--- remote ip: %s\n", connection->c_addr);
    printf("--- remote port: %s\n", video_sdp->m_port);
    printf("--- proto: %s\n", video_sdp->m_proto);
    /*setup:active/passive*/
    for (i = 0; i < video_sdp->a_attributes.nb_elt; i++) {
        sdp_attribute_t *attr = (sdp_attribute_t*)osip_list_get(&video_sdp->a_attributes, i);
        printf("--- %s : %s\n", attr->a_att_field, attr->a_att_value);
        if (strcmp(attr->a_att_field, "setup") == 0) 
            strcpy(setup, attr->a_att_value);
    }
    media.remote_ip = strdup(connection->c_addr);
    media.port = strdup(video_sdp->m_port);
    pthread_create(&tid, NULL, media_thread, &media);
    return 0;
err:
    return -1;
}

static int cmd_register()
{
	int ret = -1;
	osip_message_t *msg = NULL;
    char from[1024] = {0};
    char contact[1024] = {0};
    char proxy[1024] = {0};
    char *s;
    size_t len;

	if (app.registered){ // refresh register
		ret = eXosip_register_build_register(app.ctx, app.regid, EXPIRY, &msg);
		if (!ret){
            LOGE("registe rrefresh build failed %d", ret);
			return -1;
		}
	} else { // new register
        sprintf(from, "sip:%s@%s:%d", app.user_id, app.server_ip, USER_PORT);
        sprintf(proxy, "sip:%s@%s:%d", app.sip_id, app.server_ip, PORT);
        sprintf(contact, "sip:%s@%s:%d", app.user_id, get_ip(), USER_PORT);
		app.regid = eXosip_register_build_initial_register(app.ctx, from, proxy, contact, EXPIRY, &msg);
		if (app.regid <= 0){
            LOGE("register build failed %d", app.regid);
			return -1;
		}
    }
	ret = eXosip_register_send_register(app.ctx, app.regid, msg);
	if (ret){
        LOGE("send register error(%d)", ret);
		return ret;
	}
    osip_message_to_str(msg, &s, &len);
    LOGI("send register: \n%s", s);
	return ret;
}

static int parse_xml( const char* data, const char* s_mark, bool with_s_make, const char* e_mark, bool with_e_make, char* dest)
{
	const char* satrt = strstr( data, s_mark );

	if(satrt != NULL) {
		const char* end = strstr(satrt, e_mark);

		if(end != NULL){
			int s_pos = with_s_make ? 0 : strlen(s_mark);
			int e_pos = with_e_make ? strlen(e_mark) : 0;

			strncpy( dest, satrt+s_pos, (end+e_pos) - (satrt+s_pos) );
		}
		return 0;
	}
	return -1;
}

int catalog_handle(eXosip_event_t *evtp)
{
    char rsp_xml_body[2048] = {0}, from[512] = {0}, to[512] = {0};
    osip_message_t* rsp_msg = NULL;
    char *s;
    size_t len;

    snprintf(rsp_xml_body, sizeof(rsp_xml_body), "<?xml version=\"1.0\" encoding=\"GB2312\"?>\r\n"
            "<Response>\r\n"
            "<CmdType>Catalog</CmdType>\r\n"
            "<SN>1</SN>\r\n"
            "<DeviceID>31010100992170000071</DeviceID>\r\n"
            "<SumNum>3</SumNum>\r\n"
            "<DeviceList Num=\"3\">\r\n"
            "<Item>\r\n"
            "<DeviceID>34020000001320000001</DeviceID>\r\n"
            "<Name>Camera 01</Name>\r\n"
            "<Manufacturer>Hikvision</Manufacturer>\r\n"
            "<Model>IP Camera</Model>\r\n"
            "<Owner>Owner</Owner>\r\n"
            "<CivilCode>3101010099</CivilCode>\r\n"
            "<Address>Address</Address>\r\n"
            "<Parental>0</Parental>\r\n"
            "<ParentID>31010100992170000041</ParentID>\r\n"
            "<SafetyWay>0</SafetyWay>\r\n"
            "<RegisterWay>1</RegisterWay>\r\n"
            "<Secrecy>0</Secrecy>\r\n"
            "<Status>ON</Status>\r\n"
            "</Item>\r\n"
            "<Item>\r\n"
            "<DeviceID>34020000001320000008</DeviceID>\r\n"
            "<Name>Camera 02</Name>\r\n"
            "<Manufacturer>Hikvision</Manufacturer>\r\n"
            "<Model>IP Camera</Model>\r\n"
            "<Owner>Owner</Owner>\r\n"
            "<CivilCode>3101010099</CivilCode>\r\n"
            "<Address>Address</Address>\r\n"
            "<Parental>0</Parental>\r\n"
            "<ParentID>31010100992170000041</ParentID>\r\n"
            "<SafetyWay>0</SafetyWay>\r\n"
            "<RegisterWay>1</RegisterWay>\r\n"
            "<Secrecy>0</Secrecy>\r\n"
            "<Status>ON</Status>\r\n"
            "</Item>\r\n"
            "</DeviceList>\r\n"
            "</Response\r\n>");
    sprintf(from, "sip:%s@%s:%d", app.user_id, app.server_ip, USER_PORT);
    sprintf(to, "sip:%s@%s:%d", app.sip_id, app.server_ip, PORT);
    eXosip_message_build_request(app.ctx, &rsp_msg, "MESSAGE", to, from, NULL);
    osip_message_set_body(rsp_msg, rsp_xml_body, strlen(rsp_xml_body));
    osip_message_set_content_type(rsp_msg, "Application/MANSCDP+xml");
    eXosip_message_send_request(app.ctx, rsp_msg);	

    osip_message_to_str(rsp_msg, &s, &len);
    //LOGI("response catalog to %s: \n%s", from, s);

    return 0;
}

int message_handle(eXosip_event_t *evtp)
{
    osip_body_t* req_body = NULL;
    char cmd[64] = {0};

    osip_message_get_body(evtp->request, 0, &req_body);
    parse_xml(req_body->body, "<CmdType>", false, "</CmdType>", false, cmd);
    if (!strcmp(cmd, "Catalog")) {
        LOGI("got message: %s", cmd);
        dbg_dump_request(evtp);
        if (app.mode == MODE_CLIENT)
            catalog_handle(evtp);
        else
            response200(evtp);
    } else if (!strcmp(cmd, "Keepalive")) {
        LOGI("got message: %s", cmd);
    } else {
        LOGI("got message: %s", cmd);
    }

    return 0;
}

int sip_event_handle(eXosip_event_t *evtp)
{
    switch(evtp->type) {
        case EXOSIP_MESSAGE_NEW:
            //LOGI("EXOSIP_MESSAGE_NEW");
            if (MSG_IS_REGISTER(evtp->request)) {
                LOGI("got REGISTER");
                register_handle(evtp);
            } else if (MSG_IS_MESSAGE(evtp->request)) {
                message_handle(evtp);
            }
            break;
        case EXOSIP_CALL_ANSWERED:
            LOGI("EXOSIP_CALL_ANSWERED");
            dbg_dump_response(evtp);
            if (evtp->response) {
                invite_ack_handle(evtp);
            }
            break;
        case EXOSIP_REGISTRATION_FAILURE:
            LOGI("EXOSIP_REGISTRATION_FAILURE");
            dbg_dump_response(evtp);
            if (eXosip_add_authentication_info (app.ctx, app.user_id, app.user_id, PASSWD, NULL, NULL) < 0) {
                LOGE("add authentication info error");
                return -1;
            }
            cmd_register();
            break;
        case EXOSIP_REGISTRATION_SUCCESS:
            app.registered = 1;
            LOGI("EXOSIP_REGISTRATION_SUCCESS");
            dbg_dump_response(evtp);
            break;
        case EXOSIP_CALL_INVITE:
            LOGI("EXOSIP_CALL_INVITE");
            dbg_dump_request(evtp);
            break;
        case EXOSIP_IN_SUBSCRIPTION_NEW:
            LOGI("EXOSIP_IN_SUBSCRIPTION_NEW");
            dbg_dump_request(evtp);
            break;
        case EXOSIP_CALL_NOANSWER:
            LOGI("EXOSIP_IN_SUBSCRIPTION_NEW");
            break;
        case EXOSIP_CALL_RELEASED:
            LOGI("EXOSIP_CALL_RELEASED");
            break;
        case EXOSIP_MESSAGE_REQUESTFAILURE:
            LOGI("EXOSIP_MESSAGE_REQUESTFAILURE");
            LOGI("txt:%s", evtp->textinfo);
            LOGI("tid:%d", evtp->tid);
            if (evtp->ack) {
                char *s;
                size_t len;

                LOGI("ack not null");
                osip_message_to_str(evtp->ack, &s, &len);
                printf("%s", s);
            } else if (evtp->response) {
                LOGI("respoonse not null");
                dbg_dump_response(evtp);
            } else if (evtp->request) {
                LOGI("request not null");
            }
            break;
        case EXOSIP_MESSAGE_ANSWERED:
            LOGI("EXOSIP_MESSAGE_ANSWERED");
            dbg_dump_response(evtp);
            break;
        default:
            LOGI("msg type: %d", evtp->type);
            break;
    }
    eXosip_event_free(evtp);

    return 0;
}

static void * sip_eventloop_thread(void *arg)
{
    while(app.running) {
		osip_message_t *msg = NULL;
		eXosip_event_t *evtp = eXosip_event_wait(app.ctx, 0, 20);

		if (!evtp){
			/* auto process,such as:register refresh,auth,call keep... */
			eXosip_automatic_action(app.ctx);
			osip_usleep(100000);
			continue;
		}
        eXosip_automatic_action(app.ctx);
        //dbg_dump_request(evtp);
        sip_event_handle(evtp);
    }

    return NULL;
}

int sip_init()
{
    app.ctx = eXosip_malloc();
    if (!app.ctx) {
        LOGE("new uas context error");
        goto err;
    }
	if (eXosip_init(app.ctx)) {
        LOGE("exosip init error");
        goto err;
	}
    if (eXosip_listen_addr(app.ctx, IPPROTO_UDP, NULL, PORT, AF_INET, 0)) {
        LOGE("listen error");
        goto err;
    }
    eXosip_set_user_agent(app.ctx, UAS_VERSION);
    if (eXosip_add_authentication_info(app.ctx, app.sip_id, app.sip_id, PASSWD, NULL, NULL)){
        LOGE("add authentication info error");
        goto err;
    }
    pthread_create(&app.tid, NULL, sip_eventloop_thread, NULL);
    return 0;
err:
    
    return -1;
}

int parse_param(char *argv[])
{
    if (!argv[1]) {
        printf("usage: %s <mode>\n\tuac : sip client\n\tuas : sip server\n", argv[0]);
        goto exit;
    } else {
        if (!strcmp(argv[1], "uac")) {
            app.mode = MODE_CLIENT;
        } else if(!strcmp(argv[1], "uas")) {
            app.mode = MODE_SERVER;
        } else {
            printf("usage: %s <mode>\n\tuac : sip client\n\tuas : sip server\n", argv[0]);
            goto exit;
        }
    }

    return 0;
exit:
    return -1;
}

int main(int argc, char *argv[])
{
    if (parse_param(argv) < 0)
        goto exit;
    app.running = 1;
    app.server_ip = getenv("SIP_SERVER_IP");
    if (!app.server_ip) {
        LOGI("SIP_SERVER_IP not found");
        goto exit;
    }
    app.sip_id = getenv("SIP_SERVER_ID");
    if (!app.sip_id) {
        LOGI("SIP_SERVER_ID not found");
        goto exit;
    }
    app.relm = strndup(app.sip_id, 10);
    app.user_id = getenv("SIP_USER_ID");
    if (!app.user_id) {
        LOGI("SIP_USER_ID not found");
        goto exit;
    }
    show_info();
    if (sip_init())
        goto exit;
    while(app.running)  {
        if (app.mode == MODE_SERVER) {
            static int done = 0;

            if (app.registered && !done) {
                uas_cmd_catalog(app.user_id);
                sleep(2);
//                cmd_callstart();
                done = 1;
            } else {
            }
        } else {
            if (!app.registered) {
                LOGI("send register command to sip server");
                cmd_register();
                sleep(3);
                uac_cmd_catalog();
            }
        }
        sleep(1);
    }

exit:
    return 0;
}

