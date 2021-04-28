SHELL = /bin/bash

all: go
	cp -rf files/* go/
	cd go && dpkg-buildpackage -b -rfakeroot -us -uc

go:
	git clone -b go1.14-openssl-fips https://pagure.io/go.git go

clean:
	rm -rf go
