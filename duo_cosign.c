/*
 * Copyright (c) 2013 Andrew Mortensen
 * All rights reserved. See LICENSE.
 */

#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>

#include "duo_cosign_api.h"
#include "duo_cosign_cfg.h"
#include "duo_cosign_curl.h"
#include "duo_cosign_json.h"

extern int		errno;

char			*xname;

    static char *
dc_get_exec_name( char *exec_path )
{
    char		*exec_name;

    exec_name = strrchr( exec_path, '/' );
    if ( exec_name != NULL ) {
	exec_name++;
	if ( *exec_name == '\0' ) {
	    abort();
	}
    } else {
	exec_name = exec_path;
    }

    return( exec_name );
}

    static char *
dc_read_input_line( void )
{
    char		buf[ 512 ];
    char		*line;
    int			len;

    if ( fgets( buf, sizeof( buf ), stdin ) == NULL ) {
	fprintf( stderr, "fgets failed: %s\n", strerror( errno ));
	exit( 2 );
    }

    len = strlen( buf );
    if ( buf[ len - 1 ] != '\n' ) {
	fprintf( stderr, "fgets failed: line too long\n" );
	exit( 2 );
    }
    buf[ len - 1 ] = '\0';

    if (( line = strdup( buf )) == NULL ) {
	fprintf( stderr, "strdup failed: %s\n", strerror( errno ));
	exit( 2 );
    }

    return( line );
}
    
    int
main( int ac, char *av[] )
{
    CURL		*hcurl;
    CURLcode		rc;
    struct curl_slist	*headers = NULL;
    dc_cfg_entry_t	*cfg_list = NULL;
    dc_param_t		*params = NULL;
    dc_response_t	resp;
    char		*cfg_path;
    char		*user = NULL;
    char		*device = NULL;
    int			status;

    cfg_path = dc_get_cfg_path();

    status = dc_cfg_read( cfg_path, &cfg_list );
    if ( status < 0 ) {
	fprintf( stderr, "duo_cosign: failed to read config %s\n", cfg_path );
	exit( 2 );
    }

    if ( curl_global_init( CURL_GLOBAL_ALL ) != 0 ) {
	fprintf( stderr, "curl_global_init failed\n" );
	exit( 2 );
    }

    user = dc_read_input_line();
    device = dc_read_input_line();

    if ( dc_api_request_dispatch( DC_PING_URL_REF_ID, NULL,
		cfg_list, &resp ) < 0 ) {
	exit( 2 );
    }
    
    if ( dc_api_request_dispatch( DC_CHECK_URL_REF_ID, NULL,
		cfg_list, &resp ) < 0 ) {
	exit( 2 );
    }

    if ( user != NULL ) {
	DC_PARAMS_ADD( &params, USERNAME, user );
	dc_api_request_dispatch( DC_PREAUTH_URL_REF_ID, params,
		cfg_list, &resp );
	dc_param_list_free( &params );

	DC_PARAMS_ADD( &params, USERNAME, user );
	//DC_PARAMS_ADD( &params, FACTOR, "push" );
	//DC_PARAMS_ADD( &params, DEVICE, device );
	DC_PARAMS_ADD( &params, FACTOR, "passcode" );
	DC_PARAMS_ADD( &params, PASSCODE, device );
	dc_api_request_dispatch( DC_AUTH_URL_REF_ID, params,
		cfg_list, &resp );
	dc_param_list_free( &params );
    }

    free( user );

    curl_global_cleanup();

    return( 0 );
}

