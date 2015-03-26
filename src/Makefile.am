lib_LTLIBRARIES = libsmaug.la
libsmaug_la_SOURCES = smg_id.cc smg_id_cache.cc smg_net.cc smg_smime_association.cc \
                      smg_smime_cert.cc smg_lctr.cc smg_lctr_factory.cc smg_ad_lctr.cc \
                      smg_net_engine.cc smg_net_libunbound.cc smg_tbird.cc

libsmaug_la_LDFLAGS = $(LDFLAGS) -version-info $(libsmaug_la_version_info) \
                      -L/usr/local/lib -lunbound -lssl -lcrypto 
libsmaug_la_CXXFLAGS = $(CXXFLAGS) -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include 

noinst_PROGRAMS = test_smg_smime_cert test_smg_smime_association test_smg_id test_smg_net \
                  test_smg_id_cache
bin_PROGRAMS = smimeagen
bin_SCRIPTS = smime-gen.sh

if SMG_GETDNS
libsmaug_la_LDFLAGS += -lldns -lgetdns
libsmaug_la_SOURCES += smg_net_getdns.cc
libsmaug_la_CXXFLAGS += -D_SMG_GETDNS
endif

if SMG_LDAP
libsmaug_la_LDFLAGS += -lldap -llber 
libsmaug_la_CXXFLAGS += -DLDAP_R_COMPILE -DLDAP_LIBRARY -DLDAP_DEPRECATED 
noinst_PROGRAMS += test_smg_ldap_lctr
libsmaug_la_CXXFLAGS += -D_SMG_LDAP
endif

test_smg_smime_cert_SOURCES = test_smg_smime_cert.cc smg_smime_cert.cc
test_smg_smime_cert_LDFLAGS = -L/usr/local/lib -lcrypto $(LDFLAGS)
test_smg_smime_cert_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include $(CXXFLAGS)

test_smg_smime_association_SOURCES = test_smg_smime_association.cc smg_smime_association.cc \
                                     smg_smime_cert.cc
test_smg_smime_association_LDFLAGS = -L/usr/local/lib -lcrypto $(LDFLAGS)
test_smg_smime_association_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include $(CXXFLAGS)

test_smg_id_SOURCES = test_smg_id.cc smg_id.cc smg_smime_association.cc smg_smime_cert.cc
test_smg_id_LDFLAGS = -L/usr/local/lib -lcrypto $(LDFLAGS)
test_smg_id_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include $(CXXFLAGS)

test_smg_net_SOURCES = test_smg_net.cc smg_net.cc smg_net_engine.cc smg_net_libunbound.cc smg_id.cc \
                       smg_smime_association.cc smg_smime_cert.cc
test_smg_net_LDFLAGS = -L/usr/local/lib -lssl -lcrypto -lunbound $(LDFLAGS)
test_smg_net_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include  $(CXXFLAGS)
if SMG_GETDNS
test_smg_net_SOURCES += smg_net_getdns.cc
test_smg_net_LDFLAGS += -lldns -lgetdns
test_smg_net_CXXFLAGS += -D_SMG_GETDNS
endif

smimeagen_SOURCES = smimeagen.cc smg_id.cc smg_smime_association.cc smg_smime_cert.cc
smimeagen_LDFLAGS = -L/usr/local/lib -lssl -lcrypto $(LDFLAGS)
smimeagen_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include $(CXXFLAGS)

if SMG_LDAP
test_smg_ldap_lctr_SOURCES = test_smg_ldap_lctr.cc smg_ldap_lctr.cc smg_smime_cert.cc
test_smg_ldap_lctr_LDFLAGS = -L/usr/local/lib -lldap -llber -lssl -lcrypto
test_smg_ldap_lctr_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include \
                              -DLDAP_R_COMPILE -DLDAP_LIBRARY -DLDAP_DEPRECATED -D_SMG_LDAP
endif

test_smg_id_cache_SOURCES = test_smg_id_cache.cc smg_id.cc smg_id_cache.cc smg_smime_association.cc smg_smime_cert.cc
test_smg_id_cache_LDFLAGS = -L/usr/local/lib -lssl -lcrypto $(LDFLAGS)
test_smg_id_cache_CXXFLAGS = -g -Wall -O2 -Wno-deprecated-declarations -I/usr/local/include $(CXXFLAGS)

