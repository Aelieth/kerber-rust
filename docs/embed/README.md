# Embed

kerber-rust as the KDC inside another product.

- [klldap.md](klldap.md): the KLLDAP alignment (shared toolchain and crate
  generations) and the `KerberosSync` seam the embed implements.
- [api.md](api.md): the embed API: one store, bootstrap, kadmind, plugins, logging and sockets.
- [host-contract.md](host-contract.md): what a host store and its `HostAdmission` module must do: ownership mark, write verdicts, login verdicts, threads and locks.
