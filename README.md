## TinyCA

*Tinyca* is a very simple CA accessible via an API.

It is intended for use with programmatic ways or even tools as curl.

The application listens on the 8080 port.
Two endpoints are available with the **POST** verb :

 - /**sign**
 - /**signCSR**

The first time you request a certificate, a key/certificate couple for a self-signed certificate will be created (your CA).

All leaf certificates requested will be then authentified by this CA.

## Installation

First, install the  [Go tools](https://golang.org/dl/)  and set up your  `$GOPATH`. Then, run:

`go get github.com/jclegras/tinyca`

When using Go 1.11 or newer you don't need a $GOPATH and can instead do the following:

```
cd /ANY/PATH
git clone https://github.com/jclegras/tinyca.git
go build
## or
# go install
```

## Configuration

The application is configurable with environment variables :

 - **CAROOT** : change the directory which holds the couple key/cert for the CA (*default* : ~/.local/share/tinyca) ;
 - **KEYNAME** : change the CA key name with the given value (*default* : CAKey.pem) ;
 - **CRTNAME** : Change the CA certificate name with the given value (*default* : CACrt.pem)

## Examples

Get a key/certificate couple from your JSON request :

`curl -X POST -H "Content-Type: application.json" -d @example/data.json "localhost:8080/sign"`

Get a certificate from you base64-encoded CSR :

`curl -X POST -d @example/csr.pem.base64 "localhost:8080/signCSR`"

## Reference

[https://github.com/jsha/minica](https://github.com/jsha/minica)
[https://github.com/FiloSottile/mkcert](https://github.com/FiloSottile/mkcert)
