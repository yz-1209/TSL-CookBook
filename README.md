# TLS Brief Introduction

## SSL or TLS

When the SSL protocol was standardized by the IETF, it was renamed to Transport Layer Security ( TLS ). Many use the TLS and SSL names interchangeably, but technically, they are different, since each describes a different version of the protocol.

## Encryption, Authentication, and Integrity

The TLS protocol is designed to provide three essential services to all applications running above it: encryption, authentication, and data integrity. 

### Encryption

In order to establish a cryptographically secure data channel, the connection peers must agree on which ciphersuites will be used and the keys to encrypt the data. The TLS protocol specifies a well-defined handshake sequence to perform this exchange. 

### Authentication

As part of the TLS handshake, the protocol also allows both peers to authenticate their identity. When used in the browser, this authentication mechanism allows the client to verify that the server is who it claims to be. This verification is based on the **Chain of Trust and Certificate Authorities**. In addition, the server can optionally verify the identity of the client. 

### Integrity

The TLS protocol provides its own message framing mechanism and signs each message with a message authentication code ( MAC ). The MAC algorithm is one-way cryptopraphic hash function ( effectively a checksum ), the keys to which are negotiated by both connection peers. Whenever a TLS record is sent, a MAC value is generated and happened for that message, and receiver is then able to compute and verify the sent MAC value to ensure message integrity and authenticity. 

## TLS Handshake

Before the client and the server can begin exchanging application data over TLS, the encrypted tunnel must be negotiated: 

- The version of TLS protocol
- Choose the ciphersuite
- Verify certificates if necessary

New TLS connections require two roundtrip for a full handshake:

- The first roundtrip is used to decides on the version of TLS, a cipher suite and authenticating server's certificate.
- The second roundtrip is used to accomplish an RSA or Diffie-Hellman key exchange.

### RSA Key Exchange

The client generates a symmetric key, encrypts it with the server's public key, and sends it to the server to use as the symmetric key for the established session. In turn, the server use its private key to decrypt the sent symmetric key and the key-exchange is complete.

### Diffie-Hellman Key Exchange

### Performance of Public vs Symmetric Key Cryptography

Public-key cryptography is used only during initial setup of the TLS tunnel: the certificates are authenticated and the key exchange algorithm is executed.

Symmetric key cryptography, which uses the established symmetric key is then used to all further communication between the client and the server within the session. This is done to improve performance -- public key cryptography is much more computationally expensive.

## Server Name Indication (SNI)

The Server Name Indication (SNI) extension was introduced to the TLS protocol, which allows the client to indicate the hostname the client is attempting to connect to as part of the TLS handshake. In turn, the server is able to inspect the SNI hostname sent in the `ClientHello` message, select the appropriate certificate, and complete the TLS handshake for the desired host.

The TLS + SNI workflow is identical to `Host` header advertisement in HTTP, where the client indicates the hostname of the site it is requesting: the same IP address may host many different domains, and both `SNI` and `Host` are required to disambiguate between them.

## TLS Session Resumption

### Session Identifiers

The Session Identifiers resumption mechanism allowed the server to create and send a 32-byte session identifier as part of its `ServerHello` message during the full TLS negotiation. With the session ID in place, both the client and server can store the previously negotiated session parameters - keyed by session ID and reuse them for a subsequent session.

Specifically, the client can include the session ID in the `ClientHello` message to indicate to the server that it still remembers the negotiated cipher suite and keys from previous handshake and is able to resue them. In turn, if the server is able to find the session parameters associated with the advertised ID in its cache, then an abbreviated handshake can take place. Otherwise, a full new session negotiation is required, which will generate a new session ID.

One of the practical limitations of the Session Identifiers mechanism is the requirement for the server to create and maintain a session cache for every client. 

### Session Tickets

To address this concern for server-side deployment of TLS session caches, the "Session Ticket" replacement mechanism was introduced, which removes the requirement for the server to keep per-client session state. Instead, if the client indicates that it supports session tickets, the server can include a `New Session Ticket` record, which includes all of the negotiated session data encrypted with a secret key known only by the server.

This session ticket is then stored by the client and can be included in the `SessionTicket` extension within the `ClientHello` message of a subsequent session. Thus, all session data is stored only on the client, but the ticket is still safe because it is encrypted with a key knonwn only by the server. 

## Chain of Trust and Certificate Authorities

To understand how we can verify the peer's identity, let's examine a simple authentication workflow between Alice and Bob:

- Both Alice and Bob generate their own public and private keys.
- Both Alice and Bob hide their respective private keys.
- Alice shares her public key with Bob, and Bob shares his with Alice.
- Alice generates a new message for Bob and signs it with her private key.
- Bob uses Alice's public key to verify the provided message signature.

Public key encryption allows us to use the public key of the sender to verify that the message was signed with the right private key.

Authentication on the Web:

- Manually specified certificates: Every browser and operating system provides a mechanism for you to manually import any certificate you trust.
- Certificate authorities: A certificate authority is a trusted thrid party that is trusted by both the subject (owner) of the certificate and the party relying upon the certificate.
- The browser and the operating system: Every operating system and most browsers ship with a list of well-known certificate authorities.

The browser specifies which CAs to trust (root CAs), and the burden is then on the CAs to verify each site they sign, and to audit and verify that these certificates are not misused or compromised.

## Certificate Revocation

The Certificate themselves contain instructions on how to check if they have been revoked. Hence, to ensure that the chain of trust is not compromised, each peer can check the status of each certificate by following the embedded instructions, along with the signatures, as it verifies the certificate chain.

### Certificate Revocation List (CRL)

Certificate Revocation List is defined by RFC 5280 and specifies a simple mechanism to check the status of every certificate: each certificate authority maintains and periodically publishes a list of revoked certificate serial numbers. Anyone attempting to verify a certificate is then able to download the revocation list, cache it, and check the presence of a particular serial number within it if it is present, then it has been revoked. 

### Online Certificate Status Protocol ( OCSP )

The Online Certificate Status Protocol was introduced by RFC 2560, which provide a mechanism to perform a real-time check for status of the certificate. OCSP allows the client to query the CA's certificate database directly for just the serial number in question while validating the certificate chain.

### OCSP Stapling

Instead of the client making the OCSP request, it is the server that periodically retrieves the signed and timestamped OCSP response from the CA.

The server then appends the signed OCSP response as part of the TLS handshake, allowing the client to validate both the certificate and the attached OCSP revocation record signed by the CA.

## TLS Record Protocol

Not unlike the IP or TCP layers below it, all data exchanged within a TLS session is also framed using a well-defined protocol. The TLS Record protocol is responsible for identifying different types of message (handshake, alert, or data via the "Content Type").

A typical workflow for delivering application data is as follows:

- Record protocol receives application data.
- Received data is divided into blocks: maximum 16kb per record.
- Message authentication code ( MAC ) or HMAC is added to each record.
- Data within each record is encrypted using the negotiated cipher.

Once these steps are complete, the encrypted data is passed down to the TCP layer for transport. On the receiving end, the same workflow, but in reverse, is applied by the peer: decrypt record using negotiated cipher, verify MAC, extract and deliver the data to the application above it.

## Openssl Cheatsheet

```bash
# Display the contents of a PEM formatted certificate
openssl x509 -text -in domain.crt -noout

# Verify certificates
openssl verify -CAfile ca.crt domain.crt

# Generate a private key
openssl genrsa -out domain.key 2048

# Extract public key from a private key
openssl rsa -in domain.key -pubout -out domain_public.key

# Create CSR
openssl req -new -key domain.key -out domain.csr

# Generate a Self-signed certificate from an existing private key
openssl req -key domain.key -new -x509 -days 365 -out domain.crt

# Sign CSR
openssl x509 -req -in domain.csr -CA ca.cert -CAkey ca.key -CAcreateserial -out domain.crt

# Create a self signed certificate 
openssl req -config example-com.conf -new -x509 -sha256 -newkey rsa:2048 -nodes -keyout example-com.key -days 365 -out example-com.cert

# Create a signing request
openssl req -config example-com.conf -new -sha256 -newkey rsa:2048 -nodes -keyout example-com.key -days 365 -out example-com.csr
```

## Links

[High Performace Browser Networking, Chapter 4](https://hpbn.co/transport-layer-security-tls/)

[DigitalOcean OpenSSL Essentials](https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs)

[How to generate a self-signed SSL certificate using OpenSSL](https://stackoverflow.com/questions/10175812/how-to-generate-a-self-signed-ssl-certificate-using-openssl)