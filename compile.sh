javac -cp libs/curve25519-java-0.5.0.jar:libs/signal-protocol-java-2.8.1.jar:libs/protobuf-java-3.10.0.jar \
      -d bin \
      -Xlint:all \
      `find src -type f -name '*.java'`
