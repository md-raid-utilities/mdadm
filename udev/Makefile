INSTALL ?= /usr/bin/install
DESTDIR ?=
BINDIR ?= /sbin
PKG_CONFIG ?= pkg-config

UDEVDIR := $(shell $(PKG_CONFIG) --variable=udevdir udev 2>/dev/null)
ifndef UDEVDIR
 UDEVDIR = /lib/udev
endif

UDEV_RULES = 01-md-raid-creating.rules 63-md-raid-arrays.rules 64-md-raid-assembly.rules \
	69-md-clustered-confirm-device.rules

.PHONY: all install uninstall clean

all: $(UDEV_RULES)

%.rules: %.rules.in
	sed -e 's,BINDIR,$(BINDIR),g' $< > $@

install: $(UDEV_RULES)
	$(INSTALL) -D -m 0644 -t $(DESTDIR)$(UDEVDIR)/rules.d $^

uninstall:
	rm -f $(UDEV_RULES:%=$(DESTDIR)$(UDEVDIR)/rules.d/%)

clean:
	rm -f $(UDEV_RULES)
