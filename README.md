# secure-file-sharing-system

This repo contains a project I did for a Computer Security class at UC Berkeley. I built a cryptographic file sharing system from scratch using Golang. I wrote a design doc for the entire process, and the project had to meet design requirements like constant appendToFile operations.

The methods I implemented were InitUser, GetUser, StoreFile, AppendToFile, LoadFile, CreateInvitation, AcceptInvitation, and RevokeAccess.

I utilized RSA encryption and symmetric encryption to ensure confidentiality of the data I was sending, and to ensure integrity/auythenticity I used HMAC tags and digital signatures