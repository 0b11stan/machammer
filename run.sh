cargo build && \
  sudo setcap cap_net_raw,cap_net_admin=eip target/debug/machammer && \
  ./target/debug/machammer $@
