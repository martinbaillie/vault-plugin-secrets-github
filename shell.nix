let
  sources = import ./nix/sources.nix;
  pkgs = import sources.nixpkgs { };
in with pkgs;
mkShell {
  name = "vault-plugin-secrets-github";

  buildInputs = [
    bashInteractive
    git
    gnumake
    gnupg
    go
    golangci-lint
    gotestsum
    unzip
    vault
    which
  ];

  VAULT_ADDR = "http://localhost:8200";
  DEBUG = "true";
}
