# Copyright 2017, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

include ../Makefile.conf

ifneq ($(BUILD_FOR),OS/390)
    LDFLAGS += -shared
endif

NO_SOURCE=

ifndef PEP_MIME
    ifeq ($(BUILD_FOR),OS/390)
        LDLIBS+= -letpan-no-mt
    else
        LDLIBS+= -letpan
    endif
else
    LDLIBS+= -lpEpMIME
    NO_SOURCE+= etpan_mime.c
endif

CFLAGS+= -I../asn.1 $(EXTRA_MACROS)
CFLAGS+= -I$(PREFIX)/include
CPPFLAGS+= -DSQLITE_THREADSAFE=1

LDFLAGS+= -L../asn.1
LDFLAGS+= -L$(PREFIX)/lib
ifneq ($(BUILD_FOR),OS/390)
    LDFLAGS+= -shared
    LDLIBS+= -lc
endif
LDLIBS+= -lasn1

ifeq ($(BUILD_FOR),OS/390)
    OPENPGP=NETPGP
    LDLIBS+= -lzz
else ifeq ($(BUILD_FOR),Darwin)
    LDLIBS+= -lz -liconv
else ifeq ($(BUILD_FOR),Linux)
    CPPFLAGS+= -D_GNU_SOURCE
    LDLIBS+= -ldl -luuid
else
    $(error I do not know how to make for $(BUILD_FOR) on $(BUILD_ON))
endif

ifdef SQLITE3_FROM_OS
    NO_SOURCE+= sqlite3.c
    CPPFLAGS+= -DSQLITE3_FROM_OS
    LDLIBS+= -lsqlite3
endif

ifeq ($(OPENPGP),SEQUOIA)
    CPPFLAGS+= -DUSE_SEQUOIA
    CFLAGS+= $(SEQUOIA_CFLAGS) $(SEQUOIA_INC)
    LDFLAGS+= $(SEQUOIA_LDFLAGS)
    LDLIBS+= $(SEQUOIA_LIB)
    NO_SOURCE+=pgp_netpgp.c
else ifeq ($(OPENPGP),NETPGP)
    CPPFLAGS+= -DUSE_NETPGP
    CFLAGS+= $(NETPGP_CFLAGS) $(NETPGP_INC)
    LDFLAGS+= $(NETPGP_LDFLAGS)
    LDLIBS+= $(NETPGP_LIB)
    NO_SOURCE+=pgp_sequoia.c
else
    $(error Unknown OpenPGP library: $(OPENPGP))
endif

ALL_SOURCE=$(filter-out $(NO_SOURCE),$(wildcard *.c))
DEPENDS=$(subst .c,.d,$(ALL_SOURCE))
ALL_OBJECTS=$(subst .c,.o,$(ALL_SOURCE))
ifeq ($(BUILD_FOR),OS/390)
    ALL_OBJECTS+=/usr/lib/GSKCMS64.x
    ALL_OBJECTS+=/usr/lib/CSNPCA64.x
endif

all: $(TARGET)

-include Makefile.protocols

%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -MM $(CFLAGS) $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

# Do not generate and include the '%.d' files if cleaning or uninstalling.
ifneq ($(MAKECMDGOALS),clean)
    ifneq ($(MAKECMDGOALS),uninstall)
        -include $(DEPENDS)
    endif
endif

$(TARGET): libpEpEngine.a
	$(CC) -o $@ $(LDFLAGS) $(CFLAGS) $(ALL_OBJECTS) $(LDLIBS)

.PHONY: first all objects clean install_headers install uninstall beinstall doc

objects: $(ALL_OBJECTS)

libpEpEngine.a: $(ALL_OBJECTS)
	$(AR) -rc $@ $^

clean:
	rm -f *.d *.o *.a $(TARGET) *.dll *.so *.zip *.d.* *.def *~
	rm -Rf $(TARGET).dSYM
	rm -f *_{event,impl,fsm,func}.[ch]
	rm -rf ../doc/api/

HEADERS_TO_INSTALL = \
  pEpEngine.h keymanagement.h message_api.h dynamic_api.h stringlist.h \
  timestamp.h identity_list.h bloblist.h stringpair.h message.h mime.h group.h \
  cryptotech.h sync_api.h pEp_string.h openpgp_compat.h engine_sql.h \
  labeled_int_list.h key_reset.h base64.h sync_codec.h distribution_codec.h \
  message_codec.h storage_codec.h status_to_string.h keyreset_command.h \
  string_utilities.h \
  echo_api.h distribution_api.h media_key.h mixnet.h \
  map_asn1.h \
  platform.h platform_unix.h platform_windows.h platform_zos.h \
  pEp_debug.h pEp_log.h sql_reliability.h \
  pEpEngine_version.h \
  transport.h growing_buf.h $(wildcard ../asn.1/*.h)

# CAVEAT:
# install_headers is needed for building *STANDALONE* pEp MIME - it is NOT used for built-in functionality!!!

install_headers: $(TARGET)
	mkdir -p $(DESTDIR)$(PREFIX)/include/pEp
	cp $(HEADERS_TO_INSTALL) $(DESTDIR)$(PREFIX)/include/pEp/

# FIXME: Does anyone but Roker use install_headers? Otherwise, remove the dependency.
#        I occasionally use it.  --positron
install: $(TARGET) install_headers
	mkdir -p "$(DESTDIR)$(PREFIX)/lib/"
	cp -v $< $(DESTDIR)$(PREFIX)/lib/
	cp -v libpEpEngine.a $(DESTDIR)$(PREFIX)/lib/

beinstall: install
	cp platform*.h $(DESTDIR)$(PREFIX)/include/pEp/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/lib/$(TARGET)
	rm -f $(addprefix $(DESTDIR)$(PREFIX)/include/pEp/,$(notdir $(HEADERS_TO_INSTALL)))
	rmdir $(DESTDIR)$(PREFIX)/include/pEp 2> /dev/null || true

tags: $(wildcard *.c) $(wildcard *.h)
	ctags --sort=yes *.c *.h

doc: 
	doxygen
#	sed -i -e 's/≡/\$$\\equiv\$$/g' ../doc/api/latex/*.tex
#	make -C ../doc/api/latex

