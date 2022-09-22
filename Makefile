targetdir = $(RPM_BUILD_ROOT)
verstring = $(VERSION)

ifeq ($(strip $(targetdir)),)
	targetdir = ./target/
endif

ifeq ($(strip $(verstring)),)
	verstring = v0.0.0-dev
endif

compile:
	mkdir -p bin
	go build -ldflags="-X github.com/ipifony/vermouth.AppVersion=$(verstring)" -o bin/vermouth cmd/vermouth/main.go

install:
	mkdir -p $(targetdir)/usr/bin
	cp bin/vermouth $(targetdir)/usr/bin/vermouth
