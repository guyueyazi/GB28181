#include "public.h"
#include "osip2/osip_mt.h"
#include "eXosip2/eXosip.h"
#include "HTTPDigest.h"

#define REALM       "3402000000"
#define NONCE       "1234567890123456"
#define EXPIRY      3600
#define PORT        5060
#define UAS_VERSION "SipUASv0.1"
#define SIP_ID      "34020000002000000001"
#define PASSWD      "123456"

typedef struct {
    struct eXosip_t *ctx;
    pthread_t tid;
    int running;
} app_t;

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

static app_t app;

void dbg_dump_request(eXosip_event_t *evtp)
{
    char *s;
    size_t len;

    osip_message_to_str(evtp->request, &s, &len);
    printf("%s\n", s);
}
void dbg_dump_response(eXosip_event_t *evtp)
{
    char *s;
    size_t len;

    osip_message_to_str(evtp->response, &s, &len);
    printf("%s\n", s);
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
    osip_www_authenticate_set_realm(header,osip_enquote(core->realm));
    osip_www_authenticate_set_nonce(header,osip_enquote(core->nonce));
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

int register_handle(eXosip_event_t *evtp)
{
#define SIP_STRDUP(field) if (ss_dst->field) field = osip_strdup_without_quote(ss_dst->field)
    char *method, *algorithm, *username, *realm, *nonce, *nonce_count, *uri;
    char calc_response[HASHHEXLEN];
    osip_authorization_t * ss_dst = NULL;
    HASHHEX HA1, HA2 = "", Response;

    osip_message_get_authorization(evtp->request, 0, &ss_dst);
    if (ss_dst) {
        method = evtp->request->sip_method;
        SIP_STRDUP(algorithm);
        SIP_STRDUP(username);
        SIP_STRDUP(realm);
        SIP_STRDUP(nonce);
        SIP_STRDUP(nonce_count);
        SIP_STRDUP(uri);
        LOGI("username: %s", username);
        DigestCalcHA1(algorithm, username, realm, PASSWD, nonce, nonce_count, HA1);
        DigestCalcResponse(HA1, nonce, nonce_count, ss_dst->cnonce, ss_dst->message_qop, 0, method, uri, HA2, Response);
        if (!memcmp(calc_response, Response, HASHHEXLEN)) {
            register_response(evtp, 200);
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
        register_401unauthorized_response();
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
            dbg_dump_response(evtp);
            LOGI("EXOSIP_CALL_ANSWERED");
            if (evtp->response) {
                invite_ack_handle(evtp);
            }
            break;
    }
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
    while(app.running) 
        sleep(3);

    return 0;
}
