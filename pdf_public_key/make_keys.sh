#!/bin/sh

# Generate the key pair
openssl genpkey -algorithm RSA -aes-256-cbc -pkeyopt rsa_keygen_bits:4096 -out keys.pem

# get the public key out, in PEM format. It is the public key that we
# use for encryption. The public key can be published widely.
openssl rsa -in keys.pem -out public.pem -outform PEM -pubout
