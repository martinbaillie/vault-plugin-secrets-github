{
  description = "vault-plugin-secrets-github";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs";
  inputs.flake-utils.url = "github:numtide/flake-utils";
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      with pkgs; {
        devShell = mkShell {
          nativeBuildInputs = [
            bashInteractive
            git
            gnumake
            gnupg
            golangci-lint
            gotestsum
            go
            vault-bin
            unzip
            which
          ];

          VAULT_ADDR = "http://localhost:8200";
        };
      });
}
