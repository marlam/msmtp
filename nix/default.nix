{ system ? builtins.currentSystem }:
let
  pkgs = (import ./nixpkgs.nix {}).pkgsStatic;

  self = with pkgs; stdenv.mkDerivation rec {
    name = "msmtmp";
    src = ./..;
    doCheck = false;
    enableParallelBuilding = true;
    nativeBuildInputs = [ autoreconfHook gettext pkg-config texinfo ];
    buildInputs = [ openssl ];
    configureFlags = [
      "--prefix=/usr"
	  "--sysconfdir=/etc"
	  "--mandir=/usr/share/man"
	  "--localstatedir=/var"
      "--with-tls=openssl"
      "--with-msmtpd"
    ];
    prePatch = ''
      export LDFLAGS='-static -s -w'
      export EXTRA_LDFLAGS='-s -w -linkmode external -extldflags "-static -lm"'
    '';
    installPhase = ''
      install -Dm755 src/msmtp $out/bin/msmtp
      install -Dm755 src/msmtpd $out/bin/msmtpd
    '';
  };
in self
