# marshal

This repository contains a Java proof of concept implementation of the Marshal protocol, a variation of the Signal protocol which aims to achieve faster healing and persistent authentication.
This implementation uses the low level function of the libsignal-protocol-java library (e.g. cryptographic operations) and reimplement more abstract layers (Sessions) with adaptations for Marshal.
There is also a testing client with performance comparison between Signal and Marshal.

## Dependencies

The library has been tested on Ubuntu 20.04 with OpenJDK 11.
It use libsignal-protocol-java v 2.8.1 which itself use Google Protobuf 3.10
.0 and Curve25519 0.5.0. The dependencies are compiled as jar files in the libs folder.

## Compile and run

You can compile the project by using the compile.sh script : 
```
sh ./compile.sh
```
and the run the tests using the run.sh script : 
```
sh ./run.sh
```
