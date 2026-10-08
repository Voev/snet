#!/bin/bash


ip netns exec ns-server openssl s_server \
    -accept 10.0.1.1:8443 \
    -cert server.crt \
    -key server.key \
    -tls1_2 \
    -msg \
    -www
