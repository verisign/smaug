lib_LTLIBRARIES = libsmaug.la
libsmaug_la_SOURCES = smg_id.cc smg_id_cache.cc smg_net.cc smg_smime_association.cc \
                      smg_smime_cert.cc smg_net_engine.cc smg_net_libunbound.cc \
                      smg_pgp_association.cc smg_pgp_key.cc \
                      smg_tbird.cc 

libsmaug_la_LDFLAGS = $(LDFLAGS) -version-info $(libsmaug_la_version_info) \
                      -L/usr/local/lib -L/opt/local/lib -lunbound -lssl -lcrypto 
libsmaug_la_CXXFLAGS = $(CXXFLAGS) -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                       -I/opt/local/include

smgheaderdir = $(includedir)
smgheader_HEADERS = smg_id.h smg_id_cache.h smg_net.h smg_smime_association.h smg_smime_cert.h \
                    smg_net_engine.h smg_net_libunbound.h smg_tbird.h smg_defs.h

noinst_PROGRAMS = test_smg_smime_cert test_smg_smime_association test_smg_id test_smg_net \
                  test_smg_id_cache test_smg_pgp_association test_smg_pgp_key
bin_PROGRAMS = smimeagen openpgpkeygen

if SMG_DEBUG
libsmaug_la_CXXFLAGS += -D_SMG_DEBUG
endif

if SMG_GETDNS
libsmaug_la_LDFLAGS += -lldns -lgetdns
libsmaug_la_SOURCES += smg_net_getdns.cc
smgheader_HEADERS += smg_net_getdns.h
libsmaug_la_CXXFLAGS += -D_SMG_GETDNS
endif

test_smg_smime_cert_SOURCES = test_smg_smime_cert.cc smg_smime_cert.cc
test_smg_smime_cert_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lssl -lcrypto $(LDFLAGS)
test_smg_smime_cert_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                               -I/opt/local/include $(CXXFLAGS)

test_smg_smime_association_SOURCES = test_smg_smime_association.cc smg_smime_association.cc \
                                     smg_smime_cert.cc
test_smg_smime_association_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lssl -lcrypto $(LDFLAGS)
test_smg_smime_association_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                                      -I/opt/local/include $(CXXFLAGS)

test_smg_id_SOURCES = test_smg_id.cc smg_id.cc smg_smime_association.cc smg_smime_cert.cc \
                      smg_pgp_association.cc smg_pgp_key.cc
test_smg_id_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lssl -lcrypto -lgpgme -lgpg-error $(LDFLAGS)
test_smg_id_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                       -I/opt/local/include $(CXXFLAGS)

test_smg_net_SOURCES = test_smg_net.cc smg_net.cc smg_net_engine.cc smg_net_libunbound.cc smg_id.cc \
                       smg_smime_association.cc smg_smime_cert.cc smg_pgp_association.cc smg_pgp_key.cc
test_smg_net_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lssl -lcrypto -lgpgme -lgpg-error -lunbound $(LDFLAGS)
test_smg_net_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                       -I/opt/local/include  $(CXXFLAGS)
if SMG_GETDNS
test_smg_net_SOURCES += smg_net_getdns.cc
test_smg_net_LDFLAGS += -lldns -lgetdns
test_smg_net_CXXFLAGS += -D_SMG_GETDNS
endif

smimeagen_SOURCES = smimeagen.cc smg_id.cc smg_smime_association.cc smg_smime_cert.cc smg_pgp_association_stub.cc
smimeagen_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lssl -lcrypto $(LDFLAGS)
smimeagen_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                     -I/opt/local/include $(CXXFLAGS) -D_SMG_NO_PGP

openpgpkeygen_SOURCES = openpgpkeygen.cc smg_id.cc smg_smime_association_stub.cc smg_pgp_key.cc smg_pgp_association.cc
openpgpkeygen_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lssl -lcrypto -lgpgme -lgpg-error $(LDFLAGS)
openpgpkeygen_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                     -I/opt/local/include $(CXXFLAGS) -D_SMG_NO_SMIME

test_smg_id_cache_SOURCES = test_smg_id_cache.cc smg_id.cc smg_id_cache.cc smg_smime_association.cc \
                            smg_smime_cert.cc smg_pgp_association.cc smg_pgp_key.cc
test_smg_id_cache_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lssl -lcrypto -lgpgme -lgpg-error $(LDFLAGS)
test_smg_id_cache_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                             -I/opt/local/include $(CXXFLAGS)

test_smg_pgp_association_SOURCES = test_smg_pgp_association.cc smg_pgp_association.cc smg_pgp_key.cc 
test_smg_pgp_association_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lgpgme -lgpg-error $(LDFLAGS)
test_smg_pgp_association_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                             -I/opt/local/include $(CXXFLAGS) -D_SMG_DEBUG

test_smg_pgp_key_SOURCES = test_smg_pgp_key.cc smg_pgp_association.cc smg_pgp_key.cc 
test_smg_pgp_key_LDFLAGS = -L/usr/local/lib -L/opt/local/lib -lgpgme -lgpg-error $(LDFLAGS)
test_smg_pgp_key_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                             -I/opt/local/include $(CXXFLAGS) -D_SMG_DEBUG
