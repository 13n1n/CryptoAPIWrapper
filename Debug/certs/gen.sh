name=$1

openssl req -new -nodes -out $name-req.pem -keyout private/$name-key.pem -days 365 -config ./openssl.conf -batch
openssl ca -out $name-cert.pem -days 365 -config ./openssl.conf -infiles $name-req.pem
openssl pkcs12 -export -in $name-cert.pem -inkey private/$name-key.pem -certfile cacert.pem -name "$name's cert" -out $name-cert.p12