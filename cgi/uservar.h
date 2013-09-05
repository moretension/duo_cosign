#ifndef __USERVAR_H
#define __USERVAR_H

struct uservarlist { 
    char                *uv_var;
    char                *uv_value;
    struct uservarlist  *uv_next;
};

struct uservarlist *uservar_new( );

void uservar_dispose( struct uservarlist *l );

#endif
