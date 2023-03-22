# secureChatChannel

As the name suggests, this two-part program allows for messages to be exchanged securely in a public environment. 

## Summary

The sender, "Alice," and the receiver, "Bob," first exchange partial keys to generate the initial key. This key is then extended from 256 bits to 512 bits to create the final key. This key is then used for the methods of encryption and decryption.

The concepts and theories used are as follows:

- Elliptical Curve Cryptography (ECC)
- Decisional Diffie Helman (DDH)
- Game perfect security
- Psuedorandomness

The tools used are as follows:

- python-secrets
- python-tinyec
- python-hashlib

### Notes

These programs, while functionally secure, should not be used in the transfer of any sensitive or private information. As statistical probability would suggest, brute forcing decryption is virtually impossible. However, user error, such as writing a message longer than 512 bits or reusing keys, renders the functionality of these programs null. Additionally, please be aware of the following:

you cannot securely encrypt/decrypt:
- messages longer than 512 bits
- messages containing characters/symbols outside of the ASCII library
- by using the same key

and "Alice" and "Bob" both:
- create txt files 
- print key and message values
- delete said txt files upon the code's completion
