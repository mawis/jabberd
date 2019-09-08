with import <nixpkgs> {};

stdenv.mkDerivation {
  name = "jabberd14Env";
  buildInputs = [
    autoconf
    automake
    cmake
    expat
    gettext
    glibmm
    gnutls
    libgcrypt
    libidn
    libtasn1
    libtool
    pkg-config
    pth
    popt ];
  src = null;
  shellHook = ''
    echo "==============================================================="
    echo " You can now build the configure file with:"
    echo "  autoreconf -fi"
    echo
    echo " To build the code run ./configure and then make."
    echo "==============================================================="
  '';
}
