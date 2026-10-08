#!/bin/bash
ip netns exec ns-client openssl s_client \
    -connect 10.0.1.1:8443 \
    -servername test.local \
    -tls1_2 \
    -msg \
    -CAfile root.crt
