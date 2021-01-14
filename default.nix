let
  sources = import ./nix/sources.nix;
  pkgs = import sources.nixpkgs { };
in with pkgs;
{ version ? "master" }:
buildGoModule rec {
  inherit version;
  name = "vault-plugin-secrets-github";
  src = nix-gitignore.gitignoreSource [ ] ./.;
  nativeBuildInputs = [ which git ];

  preBuild = ''
    export buildFlagsArray=(
      -ldflags="$(make env-LDFLAGS)"
    )
  '';
  dontStrip = true;
  vendorSha256 = "16sdaqj02173xcksh8ysmj2s0lz1jz53ddaqn0nxq7qmpcyajfnc";
}
