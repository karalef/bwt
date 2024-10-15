

**Binary Web Token (BWT)**
==========================

**Overview**
------------

Binary Web Token (BWT) is a compact, URL-safe means of representing claims to be transferred between two parties. The token is digitally authenticated and contains the claims that can be verified.

**Motivation**
--------------

While JSON Web Tokens (JWT) are widely used for authentication and authorization, they have some limitations. JWTs are text-based, which can lead to increased payload size and slower processing times. BWT addresses these concerns by using a binary format, resulting in smaller token sizes and faster processing.

**Structure**
-------------

A BWT consists of three parts:

1. **Prefix**: A text prefix that contains the algorithm used for claims authentication.
2. **Claims**: A binary-encoded payload that contains the claims.
3. **Tag**: An authentication tag of the header and payload, generated using the specified algorithm.

```binary
BWT_{ALGORIGHTM}.{Base64(Binary({Claims}))}.{Base64({Tag})}
```
