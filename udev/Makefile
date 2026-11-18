INSTALL ?= /usr/bin/install
DESTDIR ?=
BINDIR ?= /sbin
PKG_CONFIG ?= pkg-config

UDEVDIR := $(shell $(PKG_CONFIG) --variable=udevdir udev 2>/dev/null)
ifndef UDEVDIR
 UDEVDIR = /lib/udev
endif

RULES = 01-md-raid-creating.rules 63-md-raid-arrays.rules 64-md-raid-assembly.rules \
	69-md-clustered-confirm-device.rules

SOURCES = udev-md-raid-creating.rules udev-md-raid-arrays.rules \
	udev-md-raid-assembly.rules udev-md-clustered-confirm-device.rules

.PHONY: install uninstall

install: $(SOURCES)
	@for file in $(RULES); \
	do sed -e 's,BINDIR,$(BINDIR),g' udev-$${file#??-} > .install.tmp && \
	   $(INSTALL) -D -m 644 .install.tmp $(DESTDIR)$(UDEVDIR)/rules.d/$$file ; \
	   rm -f .install.tmp; \
	done

uninstall:
	rm -f $(RULES:%=$(DESTDIR)$(UDEVDIR)/rules.d/%)
