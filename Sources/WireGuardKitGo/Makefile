# SPDX-License-Identifier: MIT
#
# Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

# Escape spaces in GOROOT, DESTDIR, and BUILDDIR for use in Make target/prerequisite names.
# Make uses spaces as delimiters when parsing targets, so a path like
# "/path/value one/goroot" would not be misinterpreted as two separate targets.
#
# How it works:
#   $(eval)           - expands to nothing, but the space after it is preserved
#   $(eval) <space>   - this is the "search" pattern: a literal space character
#   \ <space>         - this is the "replacement": backslash-escaped space
#   $(subst ...)      - replaces all spaces with "\ " (escaped spaces)
#
# Result: "/path/value one/goroot" becomes "/path/value\ one/goroot"
# which Make correctly parses as a single target name even if the path contains spaces.

# Regular path vs _ESCAPED path usage:
# _ESCAPED path is used in Makefile targets and prerequisites.
# Regular path is used in Makefile commands and variables.
#   You must use "" to escape the regular path when using it in commands as you do in bash.
#   Also, please note $^ will contain unescaped spaces, even if the dependency calls are _ESCAPED 🤷.

# These are generally passed to us by xcode, but we set working defaults for standalone compilation too.
ARCHS ?= x86_64 arm64
PLATFORM_NAME ?= macosx
SDKROOT ?= $(shell xcrun --sdk $(PLATFORM_NAME) --show-sdk-path)
CONFIGURATION_BUILD_DIR ?= $(CURDIR)/out
CONFIGURATION_TEMP_DIR ?= $(CURDIR)/.tmp

export PATH := $(PATH):/usr/local/bin:/opt/homebrew/bin
export CC ?= clang
LIPO ?= lipo
DESTDIR ?= $(CONFIGURATION_BUILD_DIR)
DESTDIR_ESCAPED := $(subst $(eval) ,\ ,$(DESTDIR))
BUILDDIR ?= $(CONFIGURATION_TEMP_DIR)/wireguard-go-bridge
BUILDDIR_ESCAPED := $(subst $(eval) ,\ ,$(BUILDDIR))

CFLAGS_PREFIX := $(if $(DEPLOYMENT_TARGET_CLANG_FLAG_NAME),-$(DEPLOYMENT_TARGET_CLANG_FLAG_NAME)=$($(DEPLOYMENT_TARGET_CLANG_ENV_NAME)),) -isysroot $(SDKROOT) -arch
GOARCH_arm64 := arm64
GOARCH_x86_64 := amd64
GOOS_macosx := darwin
GOOS_iphoneos := ios

UNAME := $(shell uname -m)
ifeq ($(UNAME), $(GOARCH_arm64))
	GOOS_iphonesimulator := ios
endif

build: $(DESTDIR_ESCAPED)/libwg-go.a
version-header: $(DESTDIR_ESCAPED)/wireguard-go-version.h

REAL_GOROOT := $(shell go env GOROOT 2>/dev/null)
export GOROOT := $(BUILDDIR)/goroot
GOROOT_ESCAPED := $(subst $(eval) ,\ ,$(GOROOT))
$(GOROOT_ESCAPED)/.prepared:
	echo "note: Running '$(GOROOT_ESCAPED)/.prepared' block"
	echo "note:   Working directory='$(shell pwd)'"
	echo "note:   REAL_GOROOT='$(REAL_GOROOT)'"
	echo "note:   GOROOT_ESCAPED='$(GOROOT_ESCAPED)'"

	[ -n "$(REAL_GOROOT)" ]
	mkdir -p "$(GOROOT)"

	echo "note:   rsyncing '$(REAL_GOROOT)/' to '$(GOROOT)/'"
	rsync -a --delete --exclude=pkg/obj/go-build "$(REAL_GOROOT)/" "$(GOROOT)/"

	echo "note:   patching '$(GOROOT)/' with 'goruntime-*.diff'"
	cat goruntime-*.diff | patch -p1 -f -N -r- -d "$(GOROOT)"

	echo "note:   touching '${@}'"
	touch "${@}"

define libwg-go-a
$(BUILDDIR_ESCAPED)/libwg-go-$(1).a: export CGO_ENABLED := 1
$(BUILDDIR_ESCAPED)/libwg-go-$(1).a: export CGO_CFLAGS := $(CFLAGS_PREFIX) $(ARCH)
$(BUILDDIR_ESCAPED)/libwg-go-$(1).a: export CGO_LDFLAGS := $(CFLAGS_PREFIX) $(ARCH)
$(BUILDDIR_ESCAPED)/libwg-go-$(1).a: export GOOS := $(GOOS_$(PLATFORM_NAME))
$(BUILDDIR_ESCAPED)/libwg-go-$(1).a: export GOARCH := $(GOARCH_$(1))
$(BUILDDIR_ESCAPED)/libwg-go-$(1).a: $(GOROOT_ESCAPED)/.prepared go.mod
	echo "note: Running '$(BUILDDIR_ESCAPED)/libwg-go-$(1).a' block"

	echo "note:   go build -ldflags=-w -trimpath -v -o '$(BUILDDIR)/libwg-go-$(1).a' -buildmode c-archive"
	go build -ldflags=-w -trimpath -v -o "$(BUILDDIR)/libwg-go-$(1).a" -buildmode c-archive

	echo "note:   rm -f '$(BUILDDIR)/libwg-go-$(1).h'"
	rm -f "$(BUILDDIR)/libwg-go-$(1).h"
endef
$(foreach ARCH,$(ARCHS),$(eval $(call libwg-go-a,$(ARCH))))

$(DESTDIR_ESCAPED)/wireguard-go-version.h: go.mod $(GOROOT_ESCAPED)/.prepared
	echo "note: Running '$(DESTDIR_ESCAPED)/wireguard-go-version.h' block"

	echo "note:   sed -E -n 's/.../p' '$<' > '$@'"
	sed -E -n 's/.*golang\.zx2c4\.com\/wireguard +v[0-9.]+-[0-9]+-([0-9a-f]{8})[0-9a-f]{4}.*/#define WIREGUARD_GO_VERSION "\1"/p' "$<" > "$@"

$(DESTDIR_ESCAPED)/libwg-go.a: $(foreach ARCH,$(ARCHS),$(BUILDDIR_ESCAPED)/libwg-go-$(ARCH).a)
	echo "note: Running '$(DESTDIR_ESCAPED)/libwg-go.a' block"

	echo "note:   mkdir -vp '$(DESTDIR)'"
	@mkdir -vp "$(DESTDIR)"

	echo "note:   $(LIPO) -create -output '$@' $(foreach ARCH,$(ARCHS),$(BUILDDIR_ESCAPED)/libwg-go-$(ARCH).a)"
	$(LIPO) -create -output "$@" $(foreach ARCH,$(ARCHS),$(BUILDDIR_ESCAPED)/libwg-go-$(ARCH).a)

clean:
	rm -rf "$(BUILDDIR)" "$(DESTDIR)/libwg-go.a" "$(DESTDIR)/wireguard-go-version.h"

install: build

.PHONY: clean build version-header install
