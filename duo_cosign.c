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

    static int
dc_exec_preauth( dc_cfg_entry_t *cfg )
{
    dc_preauth_result_t	presult;
    char		*user;
    char		*factor_name;
    char		*device_json;
    int			rc = 0;

    user = dc_read_input_line();

    switch ( dc_preauth( cfg, user, &presult )) {
    case DC_STATUS_AUTH_REQUIRED:
	device_json = dc_device_list_json_serialize( presult.devices );
	if ( device_json == NULL ) {
	    fprintf( stderr, "%s: failed to JSON serialize device list\n",
			xname );
	    printf( "Access denied\n" );
	    rc = 1;
	    break;
	}

	/* emit device list as a variable */
	printf( "$duo_devices_json=%s\n", device_json );

	/* json_dumps returns a malloc'd string */
	free( device_json );

	/* if we're running as userfactor check, indicate factor's required */
	factor_name = DC_CFG_FACTOR_NAME( cfg );
	printf( "%s\n", factor_name ? factor_name : _DC_FACTOR_NAME );
	break;

    case DC_STATUS_USER_ALLOWED:
	/* user is configured to bypass 2f, no stdout output */
	fprintf( stderr, "%s: user %s configured to bypass 2f\n", xname, user );
	break;

    case DC_STATUS_USER_DENIED:
	/* print error message, exit non-zero */
	printf( "Access denied\n" );
	rc = 1;
	break;

    case DC_STATUS_USER_NOT_ENROLLED:
	/* XXX add config support for auto-enrollment and prompt to enroll */
	fprintf( stderr, "%s: user %s not enrolled\n", xname, user );
	break;

    default:
	printf( "Access denied\n" );
	rc = 1;
	break;
    }

    free( user );

    return( rc );
}

    int
main( int ac, char *av[] )
{
    dc_cfg_entry_t	*cfg_list = NULL;
    dc_param_t		*params = NULL;
    dc_response_t	resp;
    char		*cfg_path;
    char		*user = NULL;
    char		*auth_type = NULL;
    char		*auth_data = NULL;
    int			status;
    time_t		tstamp;

    xname = dc_get_exec_name( av[ 0 ] );

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

#ifdef notdef
    if ( dc_ping( cfg_list, &tstamp ) != DC_STATUS_OK ) {
	fprintf( stderr, "ping failed\n" );
	exit( 2 );
    }
    fprintf( stderr, "Ping timestamp: %ld\n", tstamp );

    if ( dc_check( cfg_list, &tstamp ) != DC_STATUS_OK ) {
	fprintf( stderr, "check failed\n" );
	exit( 2 );
    }
    fprintf( stderr, "Check timestamp: %ld\n", tstamp );
#endif /* notdef */

    if ( strcmp( xname, "duo_cosign_preauth" ) == 0 ) {
	dc_exec_preauth( cfg_list );
    } else if ( strcmp( xname, "duo_cosign" ) == 0 ) {
	user = dc_read_input_line();
	auth_type = dc_read_input_line();
	auth_data = dc_read_input_line();

	DC_PARAMS_ADD( &params, USERNAME, user );
	DC_PARAMS_ADD( &params, FACTOR, auth_type );
	if ( strcmp( auth_type, "passcode" ) == 0 ) {
	    DC_PARAMS_ADD( &params, PASSCODE, auth_data );
	} else if ( strcmp( auth_type, "phone" ) == 0 ) {
	    DC_PARAMS_ADD( &params, DEVICE, auth_data );
	} else if ( strcmp( auth_type, "push" ) == 0 ) {
	    DC_PARAMS_ADD( &params, DEVICE, auth_data );
	}
	dc_api_request_dispatch( DC_AUTH_URL_REF_ID, params,
		cfg_list, &resp );
	dc_param_list_free( &params );

    }

    curl_global_cleanup();

    return( 0 );
}

