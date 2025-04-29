{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "CString";
  nativeBuildInputs = with pkgs; [
    clang
    cmake
    tmux
    gdb
  ];

  shellHook = ''
    export PATH=$PATH;${pkgs.clang}/bin
  '';
}
