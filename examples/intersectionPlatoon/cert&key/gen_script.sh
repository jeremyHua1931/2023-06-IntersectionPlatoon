#!/bin/bash

# CA : generate private key and root certificate
mkdir "CA"
cd "CA"
gmssl sm2keygen -pass 1 -out rootcakey.pem
gmssl certgen -CN ROOTCA -days 3650 -key rootcakey.pem -sm2_id ca -pass 1 -out rootcacert.pem
cd ..

# veh(different name format)
mkdir "veh"
cd "veh"
gmssl sm2keygen -pass 1 -out private_key.pem
gmssl reqgen -CN "veh" -key private_key.pem -pass 1 -out req.pem
gmssl reqsign -in req.pem -days 365 -cacert ../CA/rootcacert.pem -key ../CA/rootcakey.pem -sm2_id ca -pass 1 -out certificate.pem
cd ..

# veh.1~veh.7(one name format)
for ((x=1; x<=7; x++))
do
    folder="veh.$x"
    mkdir "$folder"
    cd "$folder"
    
    gmssl sm2keygen -pass 1 -out private_key.pem
    gmssl reqgen -CN "veh.$x" -key private_key.pem -pass 1 -out req.pem
    gmssl reqsign -in req.pem -days 365 -cacert ../CA/rootcacert.pem -key ../CA/rootcakey.pem -sm2_id ca -pass 1 -out certificate.pem
    
    cd ..
done
