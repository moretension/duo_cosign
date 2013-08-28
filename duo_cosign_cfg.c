/*
 * Copyright (c) 2013 Andrew Mortensen
 * All rights reserved. See LICENSE.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "duo_cosign_cfg.h"

extern int		errno;

    char *
dc_get_cfg_path( void )
{
    char        *path = NULL;

    path = getenv( DC_CFG_PATH_ENV_NAME );
    if ( path == NULL ) {
        path = DC_CFG_PATH_DEFAULT;
    }

    return( path );
}

    int
dc_cfg_read( char *cfg_path, dc_cfg_entry_t **cfg_list )
{
    FILE		*cfg_f;
    dc_cfg_entry_t	*cfg_ent, **cur_ent;
    char		linebuf[ LINE_MAX ];
    char		*line;
    size_t		idx, i;
    int			len, linenum = 0;
    int			rc = -1;

    assert( cfg_path != NULL );
    assert( cfg_list != NULL );

    *cfg_list = NULL;

    cfg_f = fopen( cfg_path, "r" );
    if ( cfg_f == NULL ) {
	fprintf( stderr, "dc_cfg_read: fopen %s: %s\n",
		cfg_path, strerror( errno ));
	goto done;
    }

    while ( fgets( linebuf, sizeof( linebuf ), cfg_f ) != NULL ) {
	linenum++;

	line = linebuf;
	while( isspace( *line )) {
	    line++;
	}
	if ( *line == '#' || *line == '\0' ) {
	    continue;
	}
	if ( memcmp( line, DC_CFG_LINE_FS, strlen( DC_CFG_LINE_FS )) == 0 ) {
	    fprintf( stderr, "dc_cfg_read: %s line %d: "
			"invalid config line: missing key\n",
			cfg_path, linenum );
	    continue;
	}

	len = strlen( line );
	if ( line[ len - 1 ] != '\n' ) {
	    fprintf( stderr, "dc_cfg_read: %s line %d: line too long\n",
			cfg_path, linenum );
	    goto done;
	}
	line[ len - 1 ] = '\0';

	idx = strcspn( line, DC_CFG_LINE_FS );
	if ( idx == 0 ) {
	    fprintf( stderr, "dc_cfg_read: %s line %d: invalid config line\n",
			cfg_path, linenum );
	    goto done;
	}

	if ( line[ idx + 1 ] == '\0' ) {
	    fprintf( stderr, "dc_cfg_read: %s line %d: invalid config line\n",
			cfg_path, linenum );
	    goto done;
	}

	for ( i = (idx - 1); i > 0 && isspace( line[ i ] ); i-- ) {
	    ;
	}

	cfg_ent = (dc_cfg_entry_t *)malloc( sizeof( dc_cfg_entry_t ));
	if ( cfg_ent == NULL ) {
	    fprintf( stderr, "dc_cfg_read: %s line %d: failed to allocate "
			"config entry: %s\n", cfg_path, linenum,
			strerror( errno ));
	    goto done;
	}
	memset( cfg_ent, 0, sizeof( dc_cfg_entry_t ));

	cfg_ent->key = (char *)malloc( i + 1 );
	if ( cfg_ent->key == NULL ) {
	    fprintf( stderr, "dc_cfg_read: %s line %d: malloc config "
			"entry key failed: %s\n", cfg_path, linenum,
			strerror( errno ));
	    goto done;
	}
	memcpy( cfg_ent->key, line, i + 1 );
	cfg_ent->key[ i + 1 ] = '\0';

	idx++;
	while ( isspace( line[ idx ] )) {
	    idx++;
	}

	cfg_ent->val = (char *)malloc(( len - idx ) + 1 );
	if ( cfg_ent->val == NULL ) {
	    fprintf( stderr, "dc_cfg_read: %s line %d: malloc config "
			"entry value failed: %s\n", cfg_path, linenum,
			strerror( errno ));
	    goto done;
	}
	memcpy( cfg_ent->val, &line[ idx ], len - idx );
	cfg_ent->val[ len - idx ] = '\0';

	for ( cur_ent = cfg_list;
		*cur_ent != NULL;
		cur_ent = &(*cur_ent)->next ) {
	    ;
	}

	cfg_ent->next = *cur_ent;
	*cur_ent = cfg_ent;
    }

    rc = linenum;

done:
    return( rc );
}

    char *
dc_cfg_value_for_key( dc_cfg_entry_t *cfg_list, char *key )
{
    char	*value = NULL;

    for ( ; cfg_list != NULL; cfg_list = cfg_list->next ) {
	if ( strcmp( key, cfg_list->key ) == 0 ) {
	    value = cfg_list->val;
	}
    }

    return( value );
}

    void
dc_cfg_print( dc_cfg_entry_t *cfg_list )
{
    for ( ; cfg_list != NULL; cfg_list = cfg_list->next ) {
	printf( "%s => %s\n", cfg_list->key, cfg_list->val );
    }
}

    void
dc_cfg_free( dc_cfg_entry_t **cfg_list )
{
    dc_cfg_entry_t	*cur_ent, *tmp;

    assert( cfg_list != NULL );

    for ( cur_ent = *cfg_list; cur_ent != NULL; cur_ent = tmp ) {
	tmp = cur_ent->next;

	free( cur_ent->key );
	free( cur_ent->val );
	free( cur_ent );
    }

    *cfg_list = NULL;
}

#ifdef notdef
    int
main( int ac, char *av[] )
{
    dc_cfg_entry_t	*cfg_list = NULL;
    char		*v;

    if ( ac != 2 ) {
	exit( 1 );
    }

    dc_cfg_read( av[ 1 ], &cfg_list );

    dc_cfg_print( cfg_list );

    v = dc_cfg_value_for_key( cfg_list, "identikit" );
    if ( v ) {
	printf( "VALUE: %s\n", v );
    }

    v = dc_cfg_value_for_key( cfg_list, "har har  har" );
    if ( v ) {
	printf( "VALUE: %s\n", v );
    }

    dc_cfg_free( &cfg_list );

    return( 0 );
}
#endif /* notdef */
