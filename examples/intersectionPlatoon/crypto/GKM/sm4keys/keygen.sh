#!/bin/bash

for i in {0..4}
do
    openssl rand -out sm4_key$i.key 16
done

