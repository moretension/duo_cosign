#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef __STDC__
#include <stdarg.h>
#else /* __STDC__ */
#include <varargs.h>
#endif /* __STDC__ */

#include <openssl/ssl.h>
#include "subfile.h"

    static int
process_var ( FILE *fs, struct subfile_list *sl, struct uservarlist *uv );


/* Look for sth. to replace. Return values:
 * 0: substitution happened successfully; go process the next char
 * anything else: no match was found, and return var was emitted
 *   (probably a worthless return value?)
 */

    static int
substitute( int c, struct subfile_list *sl )
{
  int 		i, j;
  static char	nasties[] = "<>(){}[]'`\" \\";

  for ( i = 0; sl[ i ].sl_letter != '\0'; i++ ) {
    if ( sl[ i ].sl_letter == c ) {
      break;
    }
  }
  if ( sl[ i ].sl_letter == '\0' ) {
    /* no match was found. emit the var. */
    putchar( '$' );
    putchar( c );
    return c;
  } else if ( sl[ i ].sl_data != NULL ) {
    if ( sl[ i ].sl_type == SUBF_STR ) {
      printf( "%s", sl[ i ].sl_data );
    } else if ( sl[ i ].sl_type == SUBF_STR_ESC ) {
      
      /* block XSS attacks while printing */
      for ( j = 0; j < strlen( sl[ i ].sl_data ); j++ ) {
	if ( strchr( nasties, sl[ i ].sl_data[ j ] ) != NULL ||
	     sl[ i ].sl_data[ j ] <= 0x1F ||
	     sl[ i ].sl_data[ j ] >= 0x7F ) {
	  
	  printf( "%%%x", sl[ i ].sl_data[ j ] );
	} else {
	  putc( sl[ i ].sl_data[ j ], stdout );
	}
      }
    }
  }

  return 0;
}

/* If not found in the list, do not emit anything. */
    static void
emit_uservar( char *varname, struct uservarlist *uv )
{
  while ( uv ) {
    if ( strcmp( varname, uv->uv_var ) ) {
      printf( "%s", uv->uv_value );
      return;
    }

    uv = uv->uv_next;
  }
}

/* return codes:
 * EOF: done processing the file
 * 0: go read the next character
 * anything else: the next unhandled character in the stream */

    static int
uservar( FILE *fs, int c, struct subfile_list *sl, struct uservarlist *uv )
{
  char 		varname[1024];
  int 		varpos = 0;

  if ( c != 'v' ) {
    return c;
  }

  /* look for ":varname<space>" */
  if ( ( c = getc ( fs ) ) == EOF ) {
    substitute( 'v', sl );
    return EOF;
  }

  if ( c != ':' ) {
    /* We have "$v" but not "$v:" */
       substitute( 'v', sl );
       return ':';
  }

  /* Read the rest of the variable name, terminated with a space */
  while ( varpos < sizeof( varname ) ) {
    if ( ( c = getc( fs ) ) == EOF ) {
      return EOF;
    }
    if ( c == '$' ) {
      /* Found a '$' terminating our variable pattern. Illegal syntax for 
       * $v:variable<sp>, so treat it as an old-school substitution */
      substitute( 'v', sl );

      /* Dump what we read so far */
      printf( ":%s", varname );

      return '$';
    }

    if ( c == ' ' ) {
      if ( varpos == 0 ) {
	/* Found a space immeditely following "$v:"; substitute the 'v', 
	 * emit the ": " */
	   substitute( 'v', sl );
	   putchar( ':' );
	   putchar( ' ' );
	   return 0;
      }

      /* So, we have a user variable in varname[]. Look for it in the
       * user var table; if found, substitute. If not found, skip (do
       * not emit). */

      emit_uservar( varname, uv );
      return 0;
    }

    varname[ varpos++ ] = c;
    varname[ varpos ] = '\0';
  }

  return 0;
}

/* return codes:
 * EOF: EOF was found; stop processing
 * 0: emitted, naught to do, go get the next char
 * anything else: new return value of c (probably worthless?)
 */

    static int
process_var ( FILE *fs, struct subfile_list *sl, struct uservarlist *uv )
{
  int		c;

  if (( c = getc( fs )) == EOF ) {
    putchar( '$' );
    return EOF;
  }
  
  if ( c == '$' ) {
    putchar( c );
    return 0;
  }
  
  if ( 1 ) {
    if ( ( c = uservar( fs, c, sl, uv ) ) == 0  ||
	 c == EOF ) {
      return c;
    }
    if ( c == '$' ) {
      /* uservar processing found the start of another 
       * variable name; need to process it, too */
      return process_var( fs, sl, uv );
    }

    putchar( c );
    return 0;
  }
  
  return substitute( c, sl );
}

    void
subfile( char *filename, struct subfile_list *sl, 
	 struct uservarlist *uv, int opts, ... )
{
    FILE	*fs;
    int 	c, i;
    va_list	vl;

    /*
     * close stdin to avoid "ap_content_length_filter: apr_bucket_read()"
     * errors, which occur in apache2 environments when a cgi starts
     * writing a response before processing all input. see:
     *
     * https://issues.apache.org/bugzilla/show_bug.cgi?id=44782
     */
    (void)close( 0 );

    if ( opts & SUBF_OPT_NOCACHE ) {
	fputs( "Expires: Mon, 16 Apr 1973 13:10:00 GMT\n"
		"Last-Modified: Mon, 16 Apr 1973 13:10:00 GMT\n"
		"Cache-Control: no-store, no-cache, must-revalidate\n"
		"Cache-Control: pre-check=0, post-check=0, max-age=0\n"
		"Pragma: no-cache\n", stdout );
    }
    if ( opts & SUBF_OPT_SETSTATUS ) {
	/* set HTTP Status header */
#ifdef __STDC__
	va_start( vl, opts );
#else /* __STDC__ */
	va_start( vl );
#endif /* __STDC__ */
	i = va_arg( vl, int );
	va_end( vl );
	if ( i < 200 || i > 600 ) {
	    /* unlikely http status code */
	    i = 200;
	}
	printf( "Status: %d\n", i );
    }
    if ( opts & SUBF_OPT_LOG ) {
#define SL_TITLE	1
#define SL_ERROR	4
	if ( sl[ SL_TITLE ].sl_data && sl[ SL_ERROR ].sl_data ) {
	    fprintf( stderr, "cosign cgi: %s: %s\n", sl[ SL_TITLE ].sl_data,
			sl[ SL_ERROR ].sl_data );
	}
    }

    fputs( "Content-type: text/html\n\n", stdout );

    if (( fs = fopen( filename, "r" )) == NULL ) {
	perror( filename );
	exit( 1 );
    }

    while (( c = getc( fs )) != EOF ) {
	if ( c == '$' ) {
	  c = process_var( fs, sl, uv );
	  if ( c == EOF ) {
	    /* At EOF, stop processing */
	    break;
	  }

	  if ( c == 0 ) {
	    /* Being told to look at the next charater in the stream */
	    continue;
	  }

	  /* else nothing to do; just keep swimming. Worthless return
	     value, which has the same action as c == 0. If there are
	     no better uses of the return value from process_var, it
	     should be rewritten to make the return value simpler.  */

	} else {
	    putchar( c );
	}
    }

    if ( fclose( fs ) != 0 ) {
	perror( filename );
    }

    return;
}