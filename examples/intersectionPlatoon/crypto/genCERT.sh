#!/bin/bash

for i in {1..7}
do
    cd "veh.$i"
    echo "Processing veh.$i..."
    openssl ecparam -genkey -name SM2 -out private_key.pem
	openssl req -new -key private_key.pem -out request.csr
	openssl x509 -req -in request.csr -CA ../CA/ca_cert.pem -CAkey ../CA/ca_key.pem -CAcreateserial -out cert.pem
    cd ..
done
