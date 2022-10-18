# Golang Keys Playground

The purpose of this repo is for me to play around with the Golang functions that manipulate cryptographic keys.

## Noteworthy Setup Steps (so I don't forget them...)

Generate RSA private key:

``` bash
openssl genrsa 2048 > keys/rsa_prac.key
```

Generate RSA public key:

``` bash
openssl rsa -in keys/rsa_prac.key -pubout > keys/rsa_prac.pub
```

Generate certificate for RSA key pair:
(left all fields blank, except set Common Name to FakeCA)

``` bash
openssl req -new -x509 -nodes -days 365000 -key keys/rsa_prac.key -out keys/rsa_prac.crt
```

Inspect certificate:

``` bash
# Certificate details.
openssl x509 -in keys/rsa_prac.crt -noout -text

# Extract public key from the certificate.
openssl x509 -pubkey -noout -in keys/rsa_prac.crt
```

## To Run

``` bash
go run main.go
```

See `output.txt` for the output of the above command.
