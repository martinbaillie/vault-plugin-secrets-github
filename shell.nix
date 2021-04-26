let
  sources = import ./nix/sources.nix;
  pkgs = import sources.nixpkgs { };
  unstable = import sources.nixpkgs-unstable { };
in with pkgs;
mkShell {
  name = "vault-plugin-secrets-github";

  buildInputs = [
    bashInteractive
    git
    gnumake
    gnupg
    golangci-lint
    gotestsum
    unstable.go
    unstable.vault-bin
    unzip
    which
  ];

  VAULT_ADDR = "http://localhost:8200";
  # VAULT_FORMAT = "json";
  # DEBUG = "true";
}
