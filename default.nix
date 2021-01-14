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
  vendorSha256 = "1spswhcl5n4kv6xm2l8bxcs9iyhh48h15hwp5y2ydynxqvkb3dkf";
}
