AUTOMAKE_OPTIONS = foreign

CC = clang
CFLAGS = -Wall
LDFLAGS = 

bin_PROGRAMS = duo_cosign
duo_cosign_SOURCES = duo_cosign.c duo_cosign_api.c duo_cosign_cfg.c \
			duo_cosign_curl.c duo_cosign_json.c
duo_cosign_CPPFLAGS = -I$(JSON_INCLUDE)
duo_cosign_LDADD = -lcurl -lcrypto $(JSON_STATIC_LIB)
duo_cosign_DEPENDENCIES=
