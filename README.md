ObjectiveC-JOSE
===============

Library for creating JSON Web Tokens (JWT), JSON Web Signature and JSON Web Encryption (JWE)

## Why?

I couldn’t find any objective-c implementations of the JOSE draft standards. This way annoying so I decided to quickly create a library to handle all the logic for me.

I intend to use this together with Socket.io (and the handily objc-socket.io library) to use JWT for authentication.

## Currently Implemented

* Create a JWS (signed but unencrypted)
* Supports all public header fields in standard

## Usage 

Not ready for use yet, it does the basic job of creating and sig

## Useful References

http://odino.org/securing-your-http-api-with-javascript-object-signing-and-encryption/

http://jose.readthedocs.org/en/latest/

http://webcache.googleusercontent.com/search?q=cache:Okq845p76ZoJ:popdevelop.com/2013/12/decode-json-web-token-jwt-in-ios-objective-c/+&cd=1&hl=en&ct=clnk&gl=hk


### RFCs (still in draft stage as at July 2014)

[JSON Web Token](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html)

[JSON Web Signature](http://self-issued.info/docs/draft-ietf-jose-json-web-encryption.html)


