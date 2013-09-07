/*
 * Copyright (c) 2013 Andrew Mortensen
 * All rights reserved. See LICENSE.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/hmac.h>

#include "duo_cosign_api.h"
#include "duo_cosign_curl.h"
#include "duo_cosign_json.h"

extern int		errno;
char			*dc_api_hostname = NULL;

    int
dc_param_list_push( dc_param_t **params, char *name, dc_param_type_t type, ... )
{
    dc_param_t		**cur;
    dc_param_t		*param = NULL;
    va_list		vl;
    int			i;

    if ( type > DC_PARAM_TYPE_MAX ) {
	errno = EINVAL;
	return( -1 );
    }

    param = (dc_param_t *)malloc( sizeof( dc_param_t ));
    if ( param == NULL ) {
	return( -1 );
    }
    memset( param, 0, sizeof( dc_param_t ));

    param->type = type;
    param->name = strdup( name );
    if ( param->name == NULL ) {
	goto error;
    }

#ifdef __STDC__
    va_start( vl, type );
#else /* __STDC__ */
    va_start( vl );
#endif /* __STDC__ */

    switch ( type ) {
    case DC_PARAM_TYPE_INT:
	param->dc_intval = va_arg( vl, int );
	break;

    case DC_PARAM_TYPE_STR:
	param->dc_strval = strdup( va_arg( vl, char * ));
	if ( param->dc_strval == NULL ) {
	    goto error;
	}
	break;

    default:
	/* XXX won't get here, right? check is above */
	goto error;
    }

    va_end( vl );

    for ( i = 0, cur = params; *cur != NULL; i++, cur = &(*cur)->next ) {
	if ( strcmp( param->name, (*cur)->name ) < 0 ) {
	    break;
	}
    }
    param->next = *cur;
    *cur = param;

    for ( ; *cur != NULL; cur = &(*cur)->next ) {
	i++;
    }

    /* return current count of params in list */
    return( i + 1 );

error:
    if ( param != NULL ) {
	if ( param->name != NULL ) {
	    free( param->name );
	}

	free( param );
    }

    return( -1 );
}

    void
dc_param_list_free( dc_param_t **params )
{
    dc_param_t		*cur, *tmp;

    assert( params != NULL );

    for ( cur = *params; cur != NULL; cur = tmp ) {
	tmp = cur->next;

	if ( cur->name != NULL ) {
	    free( cur->name );
	}
	if ( cur->type == DC_PARAM_TYPE_STR ) {
	    if ( cur->dc_strval != NULL ) {
		free( cur->dc_strval );
	    }
	}

	free( cur );
    }

    *params = NULL;
}

    static char *
dc_api_set_params( void *hc, dc_param_t *params )
{
    CURL		*hcurl = (CURL *)hc;
    dc_param_t		*cur;
    static char		post_params[ 1024 ];
    char		strint[ 32 ];
    char		*e_key, *e_val;
    char		*val;
    int			rc;
    int			len = 0;

    for ( cur = params; cur != NULL; cur = cur->next ) {
	e_key = curl_easy_escape( hcurl, cur->name, strlen( cur->name ));

	switch ( cur->type ) {
	case DC_PARAM_TYPE_INT:
	    snprintf( strint, sizeof( strint ), "%d", cur->dc_intval );
	    val = strint;
	    break;

	case DC_PARAM_TYPE_STR:
	    val = cur->dc_strval;
	    break;

	default:
	    /* XXX better options... */
	    abort();
	}

	e_val = curl_easy_escape( hcurl, val, strlen( val ));

	rc = snprintf( post_params + len, sizeof( post_params ),
			"%s=%s", e_key, e_val );

	curl_free( e_key );
	curl_free( e_val );

	if ( rc >= sizeof( post_params ) || rc < 0 ) {
	    fprintf( stderr, "POST data too long\n" );
	    return( NULL );
	}
	len += rc;

	if ( cur->next != NULL ) {
	    post_params[ len ] = '&';
	    len++;
	}
    }

    return( post_params );
}

/* the _REF_ID members are also the indices here */
duo_cosign_api_t	dc_api[] = {
    { DC_PING_URL_REF,
		DC_PING_URL_REF_ID, DC_API_GET, NULL },
    { DC_CHECK_URL_REF,
		DC_CHECK_URL_REF_ID, DC_API_GET, NULL },
    { DC_ENROLL_URL_REF,
		DC_ENROLL_URL_REF_ID, DC_API_POST, NULL },
    { DC_ENROLL_STATUS_URL_REF,
		DC_ENROLL_STATUS_URL_REF_ID, DC_API_POST, NULL },
    { DC_PREAUTH_URL_REF,
		DC_PREAUTH_URL_REF_ID, DC_API_POST, NULL },
    { DC_AUTH_URL_REF,
		DC_AUTH_URL_REF_ID, DC_API_POST, NULL },
    { DC_AUTH_URL_REF,
		DC_AUTH_URL_REF_ID, DC_API_POST, NULL },
    { DC_AUTH_STATUS_URL_REF,
		DC_AUTH_STATUS_URL_REF_ID, DC_API_GET, NULL },
};


    char *
dc_api_get_hostname( void )
{
    return( dc_api_hostname );
}

    char *
dc_api_set_hostname( char *hostname )
{
    if ( dc_api_hostname != NULL ) {
	free( dc_api_hostname );
    }

    dc_api_hostname = strdup( hostname );
    /* caller detects strdup failure */

    return( dc_api_hostname );
}

    int
dc_api_get_formatted_date( char *buf, int maxlen, int opts )
{
    struct tm		*lt;
    time_t		now = time( NULL );
    unsigned int	len = 0;

    lt = localtime( &now );

    if (( opts & DC_API_DATE_FORMAT_HEADER )) {
	len = strlen( "Date: " );
	if ( len >= maxlen ) {
	    return( 0 );
	}
	strcpy( buf, "Date: " );

	maxlen -= len;
    }

    return( strftime( buf + len, maxlen, "%a, %d %b %Y %H:%M:%S %z", lt ));
}

unsigned char	hextab[] = {
		    '0', '1', '2', '3', '4', '5', '6', '7',
		    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
		};
    int
dc_api_hmac_for_request( duo_cosign_api_t *req, dc_cfg_entry_t *cfg,
	char *params, char *hmac_hex, int maxhexlen )
{
    HMAC_CTX		ctx;
    const EVP_MD	*evp_md = EVP_sha1();
    unsigned char	md[ EVP_MAX_MD_SIZE ];
				    
    char		*p;
    char		date[ 36 ];
    char		*key;
    char		lf = '\n';
    unsigned int	len;
    int			i;

    /* ensure we have enough space for the hexchars + LF + nul */ 
    assert( maxhexlen >= ((EVP_MAX_MD_SIZE * 2) + 2 ));
    
    key = DC_CFG_VALUE( cfg, API_SKEY );
    assert( key != NULL );

    HMAC_CTX_init( &ctx );
    HMAC_Init( &ctx, (const void *)key, strlen( key ), evp_md );

    len = dc_api_get_formatted_date( date, sizeof( date ),
					DC_API_DATE_FORMAT_DEFAULT );
    if ( !len ) {
	fprintf( stderr, "duo_cosign: date buffer too small\n" );
	return( 0 );
    }

    HMAC_Update( &ctx, (const unsigned char *)date, strlen( date ));
    HMAC_Update( &ctx, (const unsigned char *)&lf, 1 );

    HMAC_Update( &ctx, (const unsigned char *)req->method,
			strlen( req->method ));
    HMAC_Update( &ctx, (const unsigned char *)&lf, 1 );

    HMAC_Update( &ctx, (const unsigned char *)dc_api_hostname,
			strlen( dc_api_hostname ));
    HMAC_Update( &ctx, (const unsigned char *)&lf, 1 );

    HMAC_Update( &ctx, (const unsigned char *)req->url_ref,
			strlen( req->url_ref ));
    HMAC_Update( &ctx, (const unsigned char *)&lf, 1 );

    if ( params ) {
	HMAC_Update( &ctx, (const unsigned char *)params,
			    strlen( params ));
    }

    HMAC_Final( &ctx, md, &len );
    HMAC_CTX_cleanup( &ctx );

    p = hmac_hex;
    for ( i = 0; i < len; i++ ) {
	*p = hextab[ ((md[ i ] & 0xf0) >> 4) ];
	*(p + 1) = hextab[ (md[ i ] & 0x0f) ];

	p += 2;
    }
    *p = '\0';

    return( p - hmac_hex );
}

#define DC_URL_SCHEME		"https://"
#define DC_URL_SCHEME_LEN	strlen( DC_URL_SCHEME )
    char *
dc_api_url_for_request( duo_cosign_api_t *req )
{
    char		*api_url;
    int			len;

    assert( dc_api_hostname != NULL );
    assert( req != NULL );

    len = DC_URL_SCHEME_LEN + strlen( dc_api_hostname ) +
		strlen( req->url_ref ) + 1;

    api_url = (char *)malloc( len );
    if ( api_url != NULL ) {
	memcpy( api_url, DC_URL_SCHEME, DC_URL_SCHEME_LEN );
	len = DC_URL_SCHEME_LEN;

	memcpy( api_url + len, dc_api_hostname, strlen( dc_api_hostname ));
	len += strlen( dc_api_hostname );

	memcpy( api_url + len, req->url_ref, strlen( req->url_ref ));
	len += strlen( req->url_ref );

	api_url[ len ] = '\0';
    }

    return( api_url );
}

    size_t
dc_process_response_data( char *data, size_t sz, size_t nmemb, void *info )
{
    dc_data_t           *dcd = (dc_data_t *)info;

    if ( dcd->len + (sz * nmemb) >= DC_API_RESPONSE_MAX ) {
        fprintf( stderr, "dc_process_response_data: response too long\n" );
        return( 0 );
    }

    memcpy( dcd->data + dcd->len, data, sz * nmemb );
    dcd->len += sz * nmemb;

    return( sz * nmemb );
}

    int
dc_api_request_dispatch( dc_url_ref_id_t req_id, dc_param_t *req_params,
	dc_cfg_entry_t *cfg, dc_response_t *response )
{
    CURL		*hcurl = NULL;
    CURLcode		rc;
    struct curl_slist	*headers = NULL;
    char		buf[ DC_API_RESPONSE_MAX ];
    dc_data_t		response_data = { 0, buf };
    dc_json_t		*jsn;
    dc_json_err_t	jsn_err;
    char		hmac_hex[ EVP_MAX_MD_SIZE * 2 + 2 ];
    char		date[ 64 ];
    char		*api_url;
    char		*params = NULL;
    int			status = DC_STATUS_FAIL;

    assert( response != NULL );

    hcurl = curl_easy_init();
    if ( hcurl == NULL ) {
	fprintf( stderr, "curl_easy_init failed\n" );
	goto done;
    }

    if ( dc_api_set_hostname( DC_CFG_VALUE( cfg, API_HOST )) == NULL ) {
	fprintf( stderr, "failed to set API hostname\n" );
	goto done;
    }

    if ( !dc_api_get_formatted_date( date, sizeof( date ),
					DC_API_DATE_FORMAT_HEADER )) {
	fprintf( stderr, "failed to get formatted date\n" );
	goto done;
    }

    if ( req_params ) {
	params = dc_api_set_params( hcurl, req_params );
    }

    if ( dc_api_hmac_for_request( &dc_api[ req_id ], cfg, params,
				hmac_hex, sizeof( hmac_hex )) == 0 ) {
	fprintf( stderr, "failed to get HMAC for request\n" );
	goto done;
    }

    api_url = dc_api_url_for_request( &dc_api[ req_id ] );
    if ( api_url == NULL ) {
	fprintf( stderr, "failed to create URL for API request: %s\n",
		strerror( errno ));
	exit( 2 );
    }
    DC_CURL_SET_URL( api_url );

    DC_CURL_SET_RESPONSE_BUFFER( &response_data );
    DC_CURL_SET_RESPONSE_CALLBACK( dc_process_response_data );	    

    headers = curl_slist_append( headers, date );
    if ( headers == NULL ) {
	fprintf( stderr, "failed to add Date header to request\n" );
	exit( 2 );
    }
    DC_CURL_SET_HEADERS( headers );

    DC_CURL_SET_USERNAME( DC_CFG_VALUE( cfg, API_IKEY ));
    DC_CURL_SET_PASSWORD( hmac_hex );

    if ( strcmp( dc_api[ req_id ].method, DC_API_POST ) == 0 ) {
	curl_easy_setopt( hcurl, CURLOPT_POSTFIELDS, params );
    }

    if ( dc_curl_set_options( hcurl ) != CURLE_OK ) {
	fprintf( stderr, "failed to set connection options\n" );
	goto done;
    }

    rc = curl_easy_perform( hcurl );
    if ( rc != CURLE_OK ) {
	fprintf( stderr, "curl request failed: %s\n",
		curl_easy_strerror( rc ));
	exit( 2 );
    }

    //write( 2, response_data.data, response_data.len );

    /* XXX this is a leaked ref. store top-level jsn in api struct? */
    jsn = duo_cosign_json_parse( response_data.data, response_data.len,
					&jsn_err );
    if ( jsn == NULL ) {
	/* XXX fill buffer with jsn_err data */
	fprintf( stderr, "JSON response parsing failed: %s "
		"(line %d, column %d, position %d)\n",
		jsn_err.text, jsn_err.line, jsn_err.column, jsn_err.position );
			
	goto done;
    }

    if ( duo_cosign_json_get_response( jsn, response ) != 0 ) {
	fprintf( stderr, "Missing or invalid data in response...\n" );
	goto done;
    }

    if ( response->type == DC_RESPONSE_TYPE_ERROR ) {
	fprintf( stderr, "API request failed: %s: %s (code %d)\n",
		response->response_error.message,
		response->response_error.detail,
		response->response_error.code );
	goto done;
    }

    status = DC_STATUS_OK;

done:
    if ( headers != NULL ) {
	curl_slist_free_all( headers );
    }
    if ( hcurl != NULL ) {
	curl_easy_cleanup( hcurl );
    }

    return( status );
}

    static void
_dc_device_set_capabilities( dc_device_t *dev, void *value )
{
    dc_json_t	*j_val = (dc_json_t *)value;
    dc_json_t	*j_str;
    const char	*capa_str;
    size_t	i, j, len;
    struct {
	char	*key;
	int	capa;
    } capa_tab[] = {
	{ DC_DEVICE_CAPA_PUSH_KEY, DC_DEVICE_CAPA_PUSH },
	{ DC_DEVICE_CAPA_PHONE_KEY, DC_DEVICE_CAPA_PHONE },
	{ DC_DEVICE_CAPA_SMS_KEY, DC_DEVICE_CAPA_SMS },
	{ NULL, DC_DEVICE_CAPA_NONE },
    };

    if ( json_typeof( j_val ) != JSON_ARRAY ) {
	fprintf( stderr, "Invalid capabilities list\n" );
	return;
    }
    
    len = json_array_size( j_val );
    for ( i = 0; i < len; i++ ) {
	j_str = json_array_get( j_val, i );
	if ( json_typeof( j_str ) != JSON_STRING ) {
	    fprintf( stderr, "Invalid entry in capabilities list\n" );
	    break;
	}
	capa_str = json_string_value( j_str );

	for ( j = 0; capa_tab[ j ].key != NULL; j++ ) {
	    if ( strcmp( capa_str, capa_tab[ j ].key ) == 0 ) {
		dev->capabilities |= capa_tab[ j ].capa;
	    }
	}
    }
}

    static void
_dc_device_set_string_value( const char **str, void *value )
{
    dc_json_t	*j_str = (dc_json_t *)value;

    assert( str != NULL );

    if ( json_typeof( j_str ) != JSON_STRING ) {
	fprintf( stderr, "Invalid non-string value for device\n" );
	return;
    }

    *str = json_string_value( j_str );
}

    static inline void
_dc_device_set_id( dc_device_t *dev, void *value )
{
    return( _dc_device_set_string_value( &dev->id, value ));
}

    static inline void
_dc_device_set_display_name( dc_device_t *dev, void *value )
{
    return( _dc_device_set_string_value( &dev->display_name, value ));
}

    static inline void
_dc_device_set_name( dc_device_t *dev, void *value )
{
    return( _dc_device_set_string_value( &dev->name, value ));
}

    static inline void
_dc_device_set_next_sms_passcode( dc_device_t *dev, void *value )
{
    return( _dc_device_set_string_value( &dev->next_sms_passcode, value ));
}

    static inline void
_dc_device_set_number( dc_device_t *dev, void *value )
{
    return( _dc_device_set_string_value( &dev->number, value ));
}

    static const char *
_dc_device_type_to_string( dc_device_type_t type )
{
    switch ( type ) {
    case DC_DEVICE_TYPE_PHONE:
	return( DC_DEVICE_TYPE_PHONE_KEY );

    case DC_DEVICE_TYPE_TOKEN:
	return( DC_DEVICE_TYPE_TOKEN_KEY );

    case DC_DEVICE_TYPE_DESKTOPTOKEN:
	return( DC_DEVICE_TYPE_DESKTOPTOKEN_KEY );

    default:
	break;
    }

    return( "unknown" );
}

    static void
_dc_device_set_type( dc_device_t *dev, void *value )
{
    dc_json_t	*j_val = (dc_json_t *)value;
    const char	*type_str;
    int		i;
    struct {
	const char		*name;
	dc_device_type_t	type;
    } type_tab[] = {
	{ DC_DEVICE_TYPE_PHONE_KEY, DC_DEVICE_TYPE_PHONE },
	{ DC_DEVICE_TYPE_TOKEN_KEY, DC_DEVICE_TYPE_TOKEN },
	{ DC_DEVICE_TYPE_DESKTOPTOKEN_KEY, DC_DEVICE_TYPE_DESKTOPTOKEN },
	{ NULL, DC_DEVICE_TYPE_UNKNOWN },
    };

    type_str = json_string_value( j_val );
    if ( type_str == NULL ) {
	return;
    }

    for ( i = 0; type_tab[ i ].name != NULL; i++ ) {
	if ( strcmp( type_str, type_tab[ i ].name ) == 0 ) {
	    break;
	}
    }

    dev->type = type_tab[ i ].type;
}

/* JSON serialize a sanitized device list, result must be free()'d */
    char *
dc_device_list_json_serialize( dc_device_t *devs )
{
    dc_json_t		*j_dev_root = NULL;
    dc_json_t		*j_dev_array = NULL;
    dc_json_t		*j_dev = NULL;
    dc_json_t		*j_capa = NULL;
    dc_device_t		*cur;
    char		*device_json = NULL;

    j_dev_root = json_object();
    if ( j_dev_root == NULL ) {
	goto done;
    }

    j_dev_array = json_array();
    if ( j_dev_array == NULL ) {
	goto done;
    }

    for ( cur = devs; cur != NULL; cur = cur->next ) {
	j_capa = json_array();
	if ( j_capa == NULL ) {
	    goto done;
	}
	if (( cur->capabilities & DC_DEVICE_CAPA_PUSH )) {
	    json_array_append_new( j_capa,
			json_string( DC_DEVICE_CAPA_PUSH_KEY ));
	}
	if (( cur->capabilities & DC_DEVICE_CAPA_PHONE )) {
	    json_array_append_new( j_capa,
			json_string( DC_DEVICE_CAPA_PHONE_KEY ));
	}
	if (( cur->capabilities & DC_DEVICE_CAPA_SMS )) {
	    json_array_append_new( j_capa,
			json_string( DC_DEVICE_CAPA_SMS_KEY ));
	}

	j_dev = json_pack( "{ssssss}",
		    DC_DEVICE_ID_KEY, cur->id,
		    DC_DEVICE_DISPLAY_NAME_KEY, cur->display_name,
		    DC_DEVICE_TYPE_KEY, _dc_device_type_to_string( cur->type ));
	if ( j_dev == NULL ) {
	    goto done;
	}

	json_object_set_new( j_dev, DC_DEVICE_CAPABILITIES_KEY, j_capa );
	j_capa = NULL;

	json_array_append_new( j_dev_array, j_dev );

	/*
	 * append_new steals the reference to the new object, no need to
	 * track j_dev after this.
	 */
	j_dev = NULL;
    }

    if ( json_object_set_new( j_dev_root,
		DC_PREAUTH_DEVICES_KEY, j_dev_array ) != 0 ) {
	fprintf( stderr, "device serialize: failed to set device array\n" );
	goto done;
    }
    j_dev_array = NULL;

    device_json = json_dumps( j_dev_root, JSON_COMPACT | JSON_SORT_KEYS );

done:
    if ( j_capa != NULL ) {
	json_decref( j_capa );
    }
    if ( j_dev != NULL ) {
	json_decref( j_dev );
    }
    if ( j_dev_array != NULL ) {
	json_decref( j_dev_array );
    }
    if ( j_dev_root != NULL ) {
	json_decref( j_dev_root );
    }

    return( device_json );
}

    static int
dc_device_list_add( dc_device_t **devs, dc_json_t *j_dev_obj )
{
    dc_device_t		**cur;
    dc_device_t		*dev = NULL;
    void		*j_iter;
    const char		*key;
    dc_json_t		*j_val;
    int			i;
    struct {
	const char	*key;
	void		(*set_val_fn)( dc_device_t *, void * );
    } dev_key_tab[] = {
	{ DC_DEVICE_CAPABILITIES_KEY, _dc_device_set_capabilities },
	{ DC_DEVICE_DISPLAY_NAME_KEY, _dc_device_set_display_name },
	{ DC_DEVICE_ID_KEY, _dc_device_set_id },
	{ DC_DEVICE_NAME_KEY, _dc_device_set_name },
	{ DC_DEVICE_NEXT_SMS_PASSCODE_KEY, _dc_device_set_next_sms_passcode },
	{ DC_DEVICE_NUMBER_KEY, _dc_device_set_number },
	{ DC_DEVICE_TYPE_KEY, _dc_device_set_type },
	{ NULL, NULL },
    };

    assert( devs != NULL );

    if ( j_dev_obj == NULL || json_typeof( j_dev_obj ) != JSON_OBJECT ) {
	return( -1 );
    }

    dev = (dc_device_t *)malloc( sizeof( dc_device_t ));
    if ( dev == NULL ) {
	return( -1 );
    }
    memset( dev, 0, sizeof( dc_device_t ));

    for ( j_iter = json_object_iter( j_dev_obj ); j_iter != NULL;
		j_iter = json_object_iter_next( j_dev_obj, j_iter )) {
	key = json_object_iter_key( j_iter );
	for ( i = 0; dev_key_tab[ i ].key != NULL; i++ ) {
	    if ( strcmp( key, dev_key_tab[ i ].key ) == 0 ) {
		j_val = json_object_iter_value( j_iter );
		dev_key_tab[ i ].set_val_fn( dev, j_val );
	    }
	}
    }

    /*
     * simple insert-at-tail. list very likely to be short, so no need to
     * maintain a tail pointer.
     */
    for ( i = 0, cur = devs; *cur != NULL; i++, cur = &(*cur)->next )
	;
    
    dev->next = *cur;
    *cur = dev;

    /* return current count of devices in list */
    return( i + 1 );
}

    static int
_dc_ping_check_internal( dc_cfg_entry_t *cfg, dc_url_ref_id_t ref_id,
	time_t *tstamp )
{
    dc_response_t	resp;
    dc_json_t		*jsn;

    if ( dc_api_request_dispatch( ref_id, NULL, cfg, &resp ) != DC_STATUS_OK ) {
	return( DC_STATUS_FAIL );
    }
    
    if ( resp.type != DC_RESPONSE_TYPE_OBJECT ) {
	return( DC_STATUS_FAIL );
    }

    jsn = json_object_get((dc_json_t *)resp.response_object,
				DC_RESPONSE_TIME_KEY );
    if ( jsn == NULL ) {
	fprintf( stderr, "ping/check: missing \"%s\" key\n",
				DC_RESPONSE_TIME_KEY );
	return( DC_STATUS_FAIL );
    }

    if ( tstamp != NULL ) {
	*tstamp = (time_t)json_integer_value( jsn );
    }

    return( DC_STATUS_OK );
}

    int
dc_ping( dc_cfg_entry_t *cfg, time_t *tstamp )
{
    return( _dc_ping_check_internal( cfg, DC_PING_URL_REF_ID, tstamp ));
}

    int
dc_check( dc_cfg_entry_t *cfg, time_t *tstamp )
{
    return( _dc_ping_check_internal( cfg, DC_CHECK_URL_REF_ID, tstamp ));
}

    static char *
_dc_get_ipaddr( void )
{
    return( getenv( "REMOTE_ADDR" ));
}

    static int
_dc_preauth_set_devices( dc_preauth_result_t *presult, void *devs )
{
    dc_json_t		*j_dev_arr = (dc_json_t *)devs;
    dc_status_t		status = DC_STATUS_FAIL;
    size_t		i, len;

    assert( presult != NULL );

    if ( json_typeof( j_dev_arr ) != JSON_ARRAY ) {
	fprintf( stderr, "Invalid device list type\n" );
	goto done;
    }

    /* done in memset below, but let's not assume */
    presult->devices = NULL;

    len = json_array_size( j_dev_arr );
    for ( i = 0; i < len; i++ ) {
	if ( dc_device_list_add( &presult->devices,
		json_array_get( j_dev_arr, i )) < 0 ) {
	    fprintf( stderr, "Failed to add device\n" );
	}
    }

    status = DC_STATUS_OK;

done:
    if ( status == DC_STATUS_FAIL ) {
	/* XXX free device list */
    }

    return( status );
}

    static int
_dc_preauth_set_result( dc_preauth_result_t *presult, void *value )
{
    dc_json_t		*jsn = (dc_json_t *)value;
    const char		*result_str;
    int			i;
    struct {
	const char	*status_str;
	dc_status_t	status;
    } result_tab[] = {
	{ DC_STATUS_AUTH_REQUIRED_STR, DC_STATUS_AUTH_REQUIRED },
	{ DC_STATUS_USER_ALLOWED_STR, DC_STATUS_USER_ALLOWED },
	{ DC_STATUS_USER_DENIED_STR, DC_STATUS_USER_DENIED },
	{ DC_STATUS_USER_NOT_ENROLLED_STR, DC_STATUS_USER_NOT_ENROLLED },
	{ NULL, DC_STATUS_FAIL },
    };

    assert( presult != NULL );

    result_str = json_string_value( jsn );
    if ( result_str == NULL ) {
	fprintf( stderr, "Invalid preauth result value\n" );
	presult->result = DC_STATUS_FAIL;
	goto done;
    }

    for ( i = 0; result_tab[ i ].status_str != NULL; i++ ) {
	if ( strcmp( result_str, result_tab[ i ].status_str ) == 0 ) {
	    presult->result = result_tab[ i ].status;
	    break;
	}
    }
    if ( result_tab[ i ].status_str == NULL ) {
	presult->result = DC_STATUS_FAIL;
    }

done:
    return( presult->result );
}

    static int
_dc_preauth_result_set_string_value( const char **str, void *str_val )
{
    dc_json_t	*j_str;

    assert( str != NULL );
    assert( str_val != NULL );

    j_str = (dc_json_t *)str_val;
    if ( json_typeof( j_str ) != JSON_STRING ) {
	fprintf( stderr, "preauth result: Non-string for string field\n" );
	return( DC_STATUS_FAIL );
    }

    *str = json_string_value( j_str );

    return( DC_STATUS_OK );
}

    static inline int
_dc_preauth_set_enroll_url( dc_preauth_result_t *presult, void *value )
{
    return( _dc_preauth_result_set_string_value( &presult->enroll_url, value ));
}

    static inline int
_dc_preauth_set_status_msg( dc_preauth_result_t *presult, void *value )
{
    return( _dc_preauth_result_set_string_value( &presult->status_msg, value ));
}

    int
dc_preauth( dc_cfg_entry_t *cfg, char *user, dc_preauth_result_t *presult )
{
    dc_param_t		*params = NULL;
    dc_response_t	resp;
    dc_status_t		status = DC_STATUS_FAIL;
    dc_json_t		*jsn;
    void		*j_iter;
    dc_json_t		*j_val;
    const char		*j_key;
    char		*ipaddr = NULL;
    int			i;
    struct {
	const char	*key;
	int		(*set_val_fn)( dc_preauth_result_t *, void * );
    } presult_fn_tab[] = {
	{ DC_PREAUTH_DEVICES_KEY, _dc_preauth_set_devices },
	{ DC_PREAUTH_ENROLL_URL_KEY, _dc_preauth_set_enroll_url },
	{ DC_PREAUTH_RESULT_KEY, _dc_preauth_set_result },
	{ DC_PREAUTH_STATUS_MSG_KEY, _dc_preauth_set_status_msg },
	{ NULL, NULL },
    };

    assert( user != NULL );
    assert( presult != NULL );

    memset( &resp, 0, sizeof( dc_response_t ));
    memset( presult, 0, sizeof( dc_preauth_result_t ));

    DC_PARAMS_ADD( &params, USERNAME, user );
    ipaddr = _dc_get_ipaddr();
    if ( ipaddr != NULL ) {
	DC_PARAMS_ADD( &params, IPADDR, ipaddr );
    }

    if ( dc_api_request_dispatch( DC_PREAUTH_URL_REF_ID, params,
		cfg, &resp ) != DC_STATUS_OK ) {
	fprintf( stderr, "preauth request failed\n" );
	goto done;
    }

    if ( resp.type != DC_RESPONSE_TYPE_OBJECT ) {
	fprintf( stderr, "dc_preauth: invalid response type\n" );
	goto done;
    }

    jsn = (dc_json_t *)resp.response_object;
    for ( j_iter = json_object_iter( jsn ); j_iter != NULL;
		j_iter = json_object_iter_next( jsn, j_iter )) {
	j_key = json_object_iter_key( j_iter );

	for ( i = 0; presult_fn_tab[ i ].key != NULL; i++ ) {
	    if ( strcmp( j_key, presult_fn_tab[ i ].key ) == 0 ) {
		j_val = json_object_iter_value( j_iter );

		if ( presult_fn_tab[ i ].set_val_fn( presult,
			j_val ) == DC_STATUS_FAIL ) { 
		    fprintf( stderr, "dc_preauth: failed to set result "
				"value for key \"%s\"\n", j_key );
 		}
	    }
	}
    }

    status = presult->result;

done:
    if ( params != NULL ) {
	dc_param_list_free( &params );
    }

    return( status );
}

    void
dc_preauth_result_clear( dc_preauth_result_t *presult )
{
    dc_device_t		*dev, *d_tmp;

    for ( dev = presult->devices; dev != NULL; dev = d_tmp ) {
	d_tmp = dev->next;

	free( dev );
    }
}

    static int
_dc_auth_result_set_result( dc_auth_result_t *aresult, void *value )
{
    dc_json_t		*jsn = (dc_json_t *)value;
    const char		*result;

    result = json_string_value( jsn );
    if ( result == NULL ) {
	return( DC_STATUS_FAIL );
    }
    
    if ( strcmp( result, DC_STATUS_USER_ALLOWED_STR ) == 0 ) {
	aresult->result = DC_STATUS_USER_ALLOWED;
    } else {
	aresult->result = DC_STATUS_USER_DENIED;
    }

    return( DC_STATUS_OK );
}

    static int
_dc_auth_result_set_string_value( const char **str, void *value )
{
    dc_json_t		*jsn = (dc_json_t *)value;

    assert( str != NULL );

    *str = json_string_value( jsn );

    return(( *str != NULL ) ? DC_STATUS_OK : DC_STATUS_FAIL );
}

    static inline int
_dc_auth_result_set_status( dc_auth_result_t *aresult, void *value )
{
    return( _dc_auth_result_set_string_value( &aresult->status, value ));
}

    static inline int
_dc_auth_result_set_status_msg( dc_auth_result_t *aresult, void *value )
{
    return( _dc_auth_result_set_string_value( &aresult->status_msg, value ));
}

    static inline int
_dc_auth_result_set_txid( dc_auth_result_t *aresult, void *value )
{
    return( _dc_auth_result_set_string_value( &aresult->txid, value ));
}

    int
dc_auth( dc_cfg_entry_t *cfg, dc_auth_t *auth, dc_auth_result_t *auth_result )
{
    dc_param_t		*params = NULL;
    dc_response_t	resp;
    dc_status_t		status = DC_STATUS_FAIL;
    dc_json_t		*jsn;
    dc_json_t		*j_val;
    const char		*j_key;
    char		*ipaddr = NULL;
    char		*type;
    void		*iter;
    int			i;
    struct {
	const char	*key;
	int		(*set_val_fn)( dc_auth_result_t *, void * );
    } authres_fn_tab[] = {
	{ DC_AUTH_RESULT_KEY, _dc_auth_result_set_result },
	{ DC_AUTH_STATUS_KEY, _dc_auth_result_set_status },
	{ DC_AUTH_STATUS_MSG_KEY, _dc_auth_result_set_status_msg },
	{ DC_AUTH_TXID_KEY, _dc_auth_result_set_txid },
	{ NULL, NULL },
    };

    assert( auth != NULL );
    assert( auth_result != NULL );

    memset( &resp, 0, sizeof( dc_response_t ));
    memset( auth_result, 0, sizeof( dc_auth_result_t ));

    auth_result->async = auth->async;

    DC_PARAMS_ADD( &params, USERNAME, auth->user );
    DC_PARAMS_ADD( &params, FACTOR, auth->factor );
    if ( strcmp( auth->factor, "passcode" ) == 0 ) {
	DC_PARAMS_ADD( &params, PASSCODE, auth->data );
    } else if ( strcmp( auth->factor, "phone" ) == 0 ) {
	DC_PARAMS_ADD( &params, DEVICE, auth->data );
    } else if ( strcmp( auth->factor, "sms" ) == 0 ) {
	DC_PARAMS_ADD( &params, DEVICE, auth->data );
    } else if ( strcmp( auth->factor, "push" ) == 0 ) {
	DC_PARAMS_ADD( &params, DEVICE, auth->data );

	type = DC_CFG_VALUE( cfg, AUTH_REQUEST_PREFIX );
	if ( type != NULL ) {
	    DC_PARAMS_ADD( &params, TYPE, type );
	}
    }

    ipaddr = _dc_get_ipaddr();
    if ( ipaddr != NULL ) {
	DC_PARAMS_ADD( &params, IPADDR, ipaddr );
    }

    if ( dc_api_request_dispatch( DC_AUTH_URL_REF_ID, params,
		cfg, &resp ) != DC_STATUS_OK ) {
	goto done;
    }

    if ( resp.type != DC_RESPONSE_TYPE_OBJECT ) {
	fprintf( stderr, "dc_auth: invalid response type\n" );
	goto done;
    }

    jsn = (dc_json_t *)resp.response_object;
    for ( iter = json_object_iter( jsn ); iter != NULL;
		iter = json_object_iter_next( jsn, iter )) {
	j_key = json_object_iter_key( iter );
	for ( i = 0; authres_fn_tab[ i ].key != NULL; i++ ) {
	    if ( strcmp( j_key, authres_fn_tab[ i ].key ) == 0 ) {
		j_val = json_object_iter_value( iter );
		if ( authres_fn_tab[ i ].set_val_fn( auth_result,
			j_val ) != DC_STATUS_OK ) {
		    fprintf( stderr, "dc_auth: failed to set value for "
				"response key \"%s\"", j_key );
		}
	    }
	}
    }

    if ( auth_result->async ) {
	status = DC_STATUS_AUTH_PENDING;
    } else {
	status = auth_result->result;
    }

done:
    dc_param_list_free( &params );

    return( status );
}

    int
dc_auth_status( dc_cfg_entry_t *cfg, char *auth_id )
{
    return( DC_STATUS_FAIL );
}
