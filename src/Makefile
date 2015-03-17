INC         :=  -I../include -I. -I/usr/include -I/usr/local/include
LIBS        := -lgetdns -lssl -lcrypto
# LIBS_DIR    := -L/usr/lib -L/opt/local/lib -L/usr/local/lib
LIBS_DIR    := -L/usr/local/lib

#CPP_SRCS    := dane_email.cpp domain_socket_srv.cpp domain_socket_client.cpp \
#	       dane_openssl_enc.cpp dane_openssl_dec.cpp dane_openssl_hash.cpp domain_client_test.cpp
# OBJS        := $(subst .cpp,.o,$(CPP_SRCS))


CPP_CORE    := dane_email.cpp dane_cert.cpp
CPP_OPENSSL := dane_openssl_enc.cpp dane_openssl_dec.cpp dane_openssl_sign.cpp dane_openssl_hash.cpp

CPP_LIBS    := $(CPP_CORE) $(CPP_OPENSSL)
OBJ         := $(subst .cpp,.o,$(CPP_LIBS))

CPP_TEST    := test_sign.cpp test_hash.cpp test_vrfy.cpp test_dane_email.cpp
OBJ_TEST    := $(subst .cpp,.o,$(CPP_TEST))

CC          := g++
## CXXFLAGS    := $(INC) -g -O0 -Wall -DDEBUG_LEVEL_HIGH=1
CXXFLAGS    := $(INC) -g -fPIC -Wall -O0 -Wall -DDEBUG_LEVEL_HIGH=1 -DDEBUG_LEVEL_MEDIUM=1
LDFLAGS     := $(LIBS_DIR) $(LIBS)

ifeq "$(PLATFORM)" ""
PLATFORM := $(shell uname)
endif

## BIN         := domain_socket_srv domain_socket_client libsmaug.so.0.7.0
ifeq "$(PLATFORM)" "Darwin"
LIB         := libsmaug.dylib.0.7.0
else
LIB         := libsmaug.so.0.7.0
endif

TEST        := $(subst .o,, $(OBJ_TEST))

%.o : %.cpp
	@echo 'Building file: $<'
	$(CC) -c $(CXXFLAGS)  -o $@ $<

all: $(LIB) build

test: $(TEST)

test_hash: dane_openssl_hash.o test_hash.o
	$(CC) test_hash.o $(OBJ) $(LDFLAGS) $(DEP_OBJ) -o $@

test_sign: dane_openssl_sign.o test_sign.o dane_email.o dane_openssl_hash.o
	$(CC) test_sign.o $(OBJ) $(LDFLAGS) $(DEP_OBJS) -o $@

test_vrfy: dane_openssl_sign.o test_vrfy.o dane_email.o dane_openssl_hash.o
	$(CC) test_vrfy.o $(OBJ) $(LDFLAGS) $(DEP_OBJS) -o $@

domain_socket_srv: $(OBJ) domain_socket_srv.o
	$(CC) domain_socket_srv.o $(OBJ) $(LDFLAGS) $(DEP_OBJS) -o $@

domain_socket_client: $(OBJ) domain_socket_client.o
	$(CC) domain_socket_client.o $(OBJ) $(LDFLAGS) $(DEP_OBJS) -o $@

dane_email_test: $(OBJ) dane_email_test.o
	$(CC) dane_email_test.o $(OBJ) $(LDFLAGS) $(DEP_OBJS) -o $@

$(LIB): $(OBJ)
ifeq "$(PLATFORM)" "Darwin"
	## on Mac
	g++ -dynamiclib -Wl,-headerpad_max_install_names,-undefined,dynamic_lookup,-compatibility_version,0.7.0,-current_version,0.7.0,-install_name,/usr/local/lib/$(LIB).dylib -o $(LIB) $(OBJ) -L/usr/lib $(LDFLAGS)
else
	$(CC) -shared -Wl,-soname,$(LIB) -o $(LIB)  $(OBJ) $(LDFLAGS)
endif

build:
	cp $(LIB) ../build

clean:
	rm -f *.o *.a *~ $(TEST_OBJ) $(TEST) $(LIB)

.PHONY: all dev test build lib 
