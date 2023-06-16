#!/bin/bash

for i in {1..7}
do
    cd "veh.$i"
    echo "Processing veh.$i..."
    gmssl ecparam -genkey -name sm2p256v1 -out private.key
	gmssl req -new -key private.key -out request.csr
	gmssl x509 -req -days 365 -in request.csr -CA ../CA/ca_certificate.crt -CAkey ../CA/ca_private.key -CAcreateserial -out certificate.crt
    cd ..
done
