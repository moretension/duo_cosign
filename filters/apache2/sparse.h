struct sinfo {
    char	si_ipaddr[ 256 ];	/* longer than need be */
    char	si_user[ 131 ];		/* 64@64\0 */
    char	si_realm[ 256 ];	/* longer than need be */
    char	si_krb5tkt[ MAXPATHLEN ];
    char	si_krb4tkt[ MAXPATHLEN ];
    time_t	si_itime;
};

int read_scookie( char *, struct sinfo * );
