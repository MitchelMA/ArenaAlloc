{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "CString";
  nativeBuildInputs = with pkgs; [
    clang
    cmake
    tmux
  ];

  shellHook = ''
    export PATH=$PATH;${pkgs.clang}/bin
  '';
}
