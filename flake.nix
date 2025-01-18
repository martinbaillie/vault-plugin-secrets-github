{
  description = "vault-plugin-secrets-github";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";

    devshell = {
      url = "github:numtide/devshell";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    gitignore = {
      url = "github:hercules-ci/gitignore.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      flake-parts,
      devshell,
      gitignore,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } ({
      systems = [
        "x86_64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
        "aarch64-linux"
      ];

      perSystem =
        {
          config,
          pkgs,
          system,
          ...
        }:
        let
          name = "vault-plugin-secrets-github";
          package = "github.com/martinbaillie/${name}";
          rev = self.rev or "dirty";
          ver = if self ? "dirtyRev" then self.dirtyShortRev else self.shortRev;
          date = self.lastModifiedDate or "19700101";
        in
        {
          _module.args.pkgs = import nixpkgs {
            inherit system;
            config.allowUnfree = true; # BSL2... Hashicorp...
            overlays = [
              devshell.overlays.default
            ];
          };

          packages.default = pkgs.buildGo123Module {
            inherit name;
            src = gitignore.lib.gitignoreSource ./.;
            env.CGO_ENABLED = 0;
            vendorHash = "sha256-hscwOZhaVL17HPUGfs8uYSQt80D4HK4W6kNdkSmsQdA=";
            flags = [ "-trimpath" ];
            ldflags = [
              "-s"
              "-w"
              "-extld ld"
              "-extldflags -static"
              "-X ${package}/github.projectName=${name}"
              "-X ${package}/github.projectDocs=https://${package}"
              "-X github.com/prometheus/common/version.BuildDate=${date}"
              "-X github.com/prometheus/common/version.Revision=${rev}"
              "-X github.com/prometheus/common/version.Version=${ver}"
              # TODO: Pass in from CI.
              "-X github.com/prometheus/common/version.Branch=main"
              "-X github.com/prometheus/common/version.BuildUser=nix"
            ];
          };

          devShells.default = pkgs.devshell.mkShell rec {
            inherit name;

            motd = builtins.concatStringsSep "\n" [
              "{2}${name}{reset}"
              "menu                              - available commands"
            ];

            env = [
              {
                name = "VAULT_ADDR";
                value = "http://127.0.0.1:8200";
              }
            ];

            packages = with pkgs; [
              bashInteractive
              coreutils
              gnugrep
              go
              golangci-lint
              goreleaser
              syft
              vault-bin
            ];

            commands =
              with pkgs;
              let
                prjRoot = "cd $PRJ_ROOT;";
              in
              [
                {
                  inherit name;
                  command = "nix run";
                  help = "build and run the project binary";
                }
                {
                  name = "build";
                  command = "nix build";
                  help = "build and run the project binary";
                }
                {
                  name = "todo";
                  command =
                    prjRoot
                    + ''
                      ${gnugrep}/bin/grep --exclude=flake.nix \
                        --exclude-dir=.direnv --color=auto --text \
                        -InRo -E ' TODO.*' .
                    '';
                  help = "show project TODO items";
                }
                {
                  name = "clean";
                  command =
                    prjRoot
                    + ''
                      echo >&2 "==> Cleaning"
                      rm -rf test result
                    '';
                  help = "clean transient files";
                }
                {
                  name = "tidy";
                  command =
                    prjRoot
                    + ''
                      echo >&2 "==> Tidying modules"
                      go mod tidy
                    '';
                  help = "clean transient files";
                }
                {
                  name = "lint";
                  command =
                    prjRoot
                    + ''
                      echo >&2 "==> Linting"
                      if [ -v CI ]; then
                        mkdir -p test
                        ${golangci-lint}/bin/golangci-lint run \
                            --out-format=checkstyle | tee test/checkstyle.xml
                      else
                        ${golangci-lint}/bin/golangci-lint run --fast
                      fi
                    '';
                  help = "lint the project (heavyweight when CI=true)";
                }
                {
                  name = "unit";
                  command =
                    prjRoot
                    + ''
                      [[ $# -eq 0 ]] && set -- "./..."
                      echo >&2 "==> Unit testing"
                      [ -v DEBUG ] && fmt=standard-verbose || fmt=short-verbose
                      mkdir -p test
                      if [ -v CI ]; then
                        ${gotestsum}/bin/gotestsum \
                            --format $fmt --junitfile test/junit.xml -- -race \
                            -coverprofile=test/coverage.out -covermode=atomic $@
                      else
                        ${gotestsum}/bin/gotestsum \
                            --format $fmt --junitfile test/junit.xml -- $@
                      fi
                    '';
                  help = "unit test the project";
                }
                {
                  name = "integration-server";
                  command =
                    prjRoot
                    + ''
                      echo >&2 "==> Integration server"
                      [ -v DEBUG ] && lvl=trace || lvl=error
                      [ ! -f "result/bin/vault-plugin-secrets-github" ] && build
                      pkill vault && sleep 2 || true
                      rm -f test/vault.pid
                      (
                      trap 'rm -f test/vault.pid' EXIT
                      ${vault-bin}/bin/vault server \
                          -dev \
                          -dev-plugin-dir=$(${coreutils}/bin/realpath result/bin) \
                          -dev-root-token-id=root \
                          -log-level=$lvl
                      ) &
                      echo $! > test/vault.pid
                      sleep 2
                      ${vault-bin}/bin/vault write sys/plugins/catalog/${name} \
                          sha_256=$(${coreutils}/bin/sha256sum result/bin/${name} |
                                    cut -d' ' -f1) command=${name}
                      ${vault-bin}/bin/vault secrets enable \
                          -path=github -plugin-name=${name} plugin
                    '';
                  help = "run a background Vault with the plugin enabled";
                }
                {
                  name = "integration";
                  # To run integration tests against a real GitHub App
                  # installation:
                  # $ env \
                  #   BASE_URL=https://api.github.com \
                  # 	APP_ID=<your application id> \
                  #	  ORG_NAME=<org_name> \
                  #	  INSTALLATION_ID=<installation_id> \
                  # 	PRV_KEY="$(cat /path/to/your/app/prv_key_file)" integration
                  #
                  # NOTE: this will automatically skip racyness tests to avoid
                  # GitHub API rate limiting.
                  command =
                    prjRoot
                    + ''
                      echo >&2 "==> Integration testing"
                      [ ! -f "test/vault.pid" ] && integration-server
                      unit -count 1 -tags integration ./...
                    '';
                  help = "unit and integration test the project";
                }
              ];
          };
        };
    });
}
