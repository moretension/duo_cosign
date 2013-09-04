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
    
    key = DC_CFG_API_SKEY( cfg );
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
fprintf( stderr, "api_url: %s\n", api_url );
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

    if ( dc_api_set_hostname( DC_CFG_API_HOST( cfg )) == NULL ) {
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

    DC_CURL_SET_USERNAME( DC_CFG_API_IKEY( cfg ));
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

    write( 2, response_data.data, response_data.len );

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
