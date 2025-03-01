# Blind Signature Protocol

The RSA Blind signature protocol is a two-party protocol between a client and server where they interact to compute sig=Sign(sk, input_msg), where input_msg = Prepare(msg) is a prepared version of the private message that is sent by the client and the sk, is the private signing key provided by the server.

This protocol comprises five functions

Prepare
Blind
BlindSign
Finalize
verification
It also requires one round of interaction between the client and the server.

## Assumptions for the protocol:



let msg be the client's private input message and let (sk, pk) be the server's private and public pair. 



The protocol begins by the client preparing the message to be signed by computing:


```
input_msg = Prepare(msg)
```


The client then initiates the blind signature protocol by computing:


```
blinded_msg, inv = Blind(pk, input_msg)
```


The client then sends blinded_msg to the server, which then processes the message by computing:


```
blind_sig = BlindSign(sk, blinded_msg)
```


The server then sends blind_sig to the client, which then finalizes the protocol by computing:


```
 sig = Finalize(pk, input_msg, blind_sig, inv)
```


## Functions Used in the Protocol

### Prepare

It is the process in which the message to be signed and verified is prepared for input. In this there are two types of preparation function first is an identity preparation and second is a randomized preparation function.
The identity preparation function returns the input message without transformation i.e msg = PrepareIdentity(msg).

The randomize function preparation arguments the input message with newly generated randomness. it is denoted by the function PreapareRandomize(msg), it taked input a message (msg) and gives ouput a randomized input message.

### Implementation

Inputs :
msg, message to be signed, a byte string

outputs :
input msg, a byte string that is 32 bytes longer than msg.
```
Steps :-
1. msg_prefix = random(32 or 64 ) bit
2. input_msg = concat(msg_prefix,msg)
3. output input_msg
```
### 1. Blind :

This function encrypt the input message and blinds it with the public key of the server. It outputs the blinded message to be sent to the server, encoded as a byte string and the related inverse, an integer.
Let assume the if the function fails with any error, implementations should try the function again. This function initialize RSAVP1, which is defined to throw an optional error invalid inputs.

#### 1.1 Blind(pk, msg)
```


Parameters:
1. modulus_len, the length in bytes of the RDA modulus n
2. Hash, has function is used to hash the message
3. MGF, mask generation function
4. salt_len, the length in the bytes of the salt (denoted sLen in RFC 8017)
```
Inputs:
1. pk, server public key(n,e)
2. msg, message to be signed, a byte string

outputs:
1. blinded_msg, a byte string of the length modulus_len
2. inv, an integer used to unblind the signature in Finalize
    1.encoded_msg = EMSA-PSS-ENCODE(msg, bit_len(n))with Hash, MGF, and salt_len as defined in the parameters


### 2. Blinded Sign
BlindedSign perform operation on RSA private key on the client's blinded message input and returns the output encrypted as a byte string.
BlindSign(sk, blinded_msg)
Parameters:
modulus_len, the length in the bytes of the RSA modulus n

Inputs:
1. sk, private key of the server
2. blinded_msg, encoded and blinded message to be signed, a byte string.

Outputs:
blind_msg, encrypted and blinded message to be signed, a byte string.


### 3. Finalize
The sept validates the response of the server and unblind the message to produce signature, verifies it for the correctness and outputs the signature upon the success. Parameters:
modulus_len, the length in bytes of the RSA modulus n

Parameter:

Hash, the hash function used to hash the message
MGF, the mask generation function
salt_len, the length in bytes of the salt (denoted sLen in RFC 8017)
Inputs:

pk, server public key (n, e)
msg, message to be signed, a byte string
blind_sig, signed and blinded element, a byte string of
length modulus_len
inv, inverse of the blind, an integer
Outputs:

sig, a byte string of length modulus_len


### 4. Verification
The output of the protocol is prepared message input_msg and the signature_sig. The message that get input is used in msg, from which input_msg is derived.
At last the client verifies the message signature using the public key of the server pk by invoking the RSASSA-PSS-VERIFY routine.