# Maintainer: Your Name <youremail@domain.com>
pkgname=tcpsnitch-git
pkgver=r435.c1420a0
pkgver() {
    cd "$pkgname"
    printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)" 
}
pkgrel=1
pkgdesc="A tracing tool designed to investigate the interactions between an application, the TCP/IP stack and the network."
arch=(i386 x86_64)
url="https://github.com/GregoryVds/tcpsnitch"
license=('unknown')
depends=(jansson curl libpcap)
makedepends=('git')
install=
source=('tcpsnitch-git::git+https://github.com/GregoryVds/tcpsnitch.git')
md5sums=('SKIP')

build() {
	cd "$srcdir/${pkgname}"
	./configure
	make
}

package() {
	cd "$srcdir/${pkgname}"
	make DESTDIR="$pkgdir/" install
}
