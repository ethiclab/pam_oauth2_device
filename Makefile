UNAME = $(shell uname -s)

ifeq ($(UNAME),Linux)
	PAM_MOD_PATH := /lib64/security
endif

ifeq ($(UNAME),Darwin)
	PAM_MOD_PATH := /usr/lib/pam
endif

ifeq ($(UNAME),FreeBSD)
	PAM_MOD_PATH := /usr/lib
endif

ifndef PAM_MOD_PATH
	$(error Unknown operating system!)
endif

PROG :=libpam_oauth2_device.so
OUTPUT :=pam_oauth2_device.so
CONF_NAME :=device-flow-auth

DEBUG ?=

ifdef DEBUG
  $(info debug is $(DEBUG))
  RELEASE :=
  TARGET := debug
else
  RELEASE := --release
  TARGET := release
endif

default: test build

build:
	cargo build $(RELEASE)

install:
	cp target/$(TARGET)/$(PROG) $(PAM_MOD_PATH)/$(OUTPUT)
	cp conf/$(CONF_NAME) /etc/pam.d/
	mkdir -p /etc/pam_oauth2_device
	cp config.json /etc/pam_oauth2_device/example-config.json
	gcc -o target/pam_test test.c -lpam -lpam_misc
test:
	cargo test $(RELEASE)

uninstall:
	rm $(PAM_MOD_PATH)/$(OUTPUT)

clean:
	cargo clean

all: test build install
