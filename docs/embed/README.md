# Embed

kerber-rust as the KDC inside another product.

- [klldap.md](klldap.md): what KLLDAP uses of kerber-rust.
- [api.md](api.md): the embed API: one store, bootstrap, kadmind, plugins, logging and sockets.
- [host-contract.md](host-contract.md): what a host store and its `HostAdmission` module must do: ownership mark, write verdicts, login verdicts, threads and locks.
- [password-interface.md](password-interface.md): each password write's path to a host, and where
  it differs from MIT.
