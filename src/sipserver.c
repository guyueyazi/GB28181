#include <ifaddrs.h>
#include "public.h"
#include "osip2/osip_mt.h"
#include "eXosip2/eXosip.h"
#include "HTTPDigest.h"

#define REALM       "3402000000"
#define NONCE       "1234567890123456"
#define EXPIRY      3600
#define PORT        5060
#define UAS_VERSION "SipUAv0.1"//"SipUASv0.1"
#define SIP_ID      "34020000002000000001"
#define PASSWD      "123456"
#define TIMEOUT     1800
#define RTP_PORT    18040

typedef struct {
    struct eXosip_t *ctx;
    pthread_t tid;
    int running;
    int callid;
    char user_id[64];
    char user_ip[64];
    int user_port;
} app_t;

static app_t app;

void show_info()
{
    printf("--- sip id: \t%s\n", SIP_ID);
    printf("--- passwd: \t%s\n", PASSWD);
    printf("--- realm: \t%s\n", REALM);
    printf("--- nonce: \t%s\n", NONCE);
    printf("--- expiry: \t%d\n", EXPIRY);
    printf("--- port: \t%d\n", PORT);
    printf("--- transport: \tudp\n");
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
    if (!ret && !reg) {
        eXosip_lock(app.ctx);
        eXosip_message_send_answer (app.ctx, evtp->tid, code, reg);
        eXosip_unlock(app.ctx);
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
    osip_www_authenticate_set_realm(header,osip_enquote(REALM));
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

    DigestCalcHA1("REGISTER", username, REALM, PASSWD, NONCE, NULL, HA1);
    DigestCalcResponse(HA1, NONCE, NULL, NULL, NULL, 0, method, uri, NULL, rresponse);
    memcpy(response, rresponse, HASHHEXLEN);
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
    sprintf(from, "sip:%s@%s:%d", SIP_ID, ip, PORT);
    sprintf(contact, "sip:%s@%s:%d", SIP_ID, ip, PORT);
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
            "f=\r\n", SIP_ID, ip, ip, RTP_PORT);
	ret = eXosip_call_build_initial_invite(app.ctx, &msg, to, from,  NULL, NULL);
	if (ret) {
		LOGE( "call build failed %s %s ret:%d", from, to, ret);
		return -1;
	}

	snprintf(head, sizeof(head)-1, "<%s;lr>", "");
	osip_list_special_free(&msg->routes, (void(*)(void*))osip_route_free);
	osip_message_set_route(msg, head);
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
            strcpy(app.user_ip, contact->url->host);
            app.user_port = atoi(contact->url->port);
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
            LOGI("register_success");
            //sleep(3);
            //LOGI("start call");
            //cmd_callstart();

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



int invite_ack_handle(eXosip_event_t *evtp)
{
    int code, i;
    char setup[64];
    osip_message_t* ack;
    sdp_message_t *sdp_msg;
    sdp_connection_t *connection;
    sdp_media_t * video_sdp;

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
        LOGI("--- %s : %s\n", attr->a_att_field, attr->a_att_value);
        if (strcmp(attr->a_att_field, "setup") == 0) 
            strcpy(setup, attr->a_att_value);
    }
    return 0;
err:
    return -1;
}

int sip_event_handle(eXosip_event_t *evtp)
{
    switch(evtp->type) {
        case EXOSIP_MESSAGE_NEW:
            dbg_dump_request(evtp);
            if (MSG_IS_REGISTER(evtp->request)) {
                LOGI("get REGISTER");
                register_handle(evtp);
            }
            break;
        case EXOSIP_CALL_ANSWERED:
            LOGI("EXOSIP_CALL_ANSWERED");
            dbg_dump_response(evtp);
            if (evtp->response) {
                invite_ack_handle(evtp);
            }
            break;
        case EXOSIP_REGISTRATION_SUCCESS:
            LOGI("EXOSIP_REGISTRATION_SUCCESS");
            break;
        case EXOSIP_REGISTRATION_FAILURE:
            LOGI("EXOSIP_REGISTRATION_FAILURE");
            break;
        case EXOSIP_CALL_INVITE:
            LOGI("EXOSIP_CALL_INVITE");
            break;
        case EXOSIP_CALL_REINVITE:
            LOGI("EXOSIP_CALL_REINVITE");
            break;
        case EXOSIP_CALL_PROCEEDING:
            LOGI("EXOSIP_CALL_PROCEEDING");
            break;
        case EXOSIP_CALL_NOANSWER:
            LOGI("EXOSIP_CALL_NOANSWER");
            break;
        case EXOSIP_CALL_REQUESTFAILURE:
            LOGI("EXOSIP_CALL_REQUESTFAILURE");
            break;
		case EXOSIP_CALL_GLOBALFAILURE:
            LOGI("EXOSIP_CALL_GLOBALFAILURE");
            break;
		case EXOSIP_CALL_SERVERFAILURE:
            LOGI("EXOSIP_CALL_SERVERFAILURE");
            break;
        case EXOSIP_CALL_ACK:
            LOGI("EXOSIP_CALL_ACK");
            break;
        case EXOSIP_CALL_CLOSED:
            LOGI("EXOSIP_CALL_CLOSED");
            break;
        case EXOSIP_CALL_CANCELLED:
            LOGI("EXOSIP_CALL_CANCELLED");
            break;
        case EXOSIP_CALL_RELEASED:
            LOGI("EXOSIP_CALL_RELEASED");
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
        sip_event_handle(evtp);
    }

    return NULL;
}

int sipserver_init()
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
    if (eXosip_add_authentication_info(app.ctx, SIP_ID, SIP_ID, PASSWD, NULL, NULL)){
        LOGE("add authentication info error");
        goto err;
    }
    pthread_create(&app.tid, NULL, sip_eventloop_thread, NULL);
    return 0;
err:
    
    return -1;
}

int main()
{
    show_info();
    app.running = 1;
    if (sipserver_init())
        return 0;
    sleep(5);
    cmd_callstart();
    while(app.running) 
        sleep(3);

    return 0;
}
