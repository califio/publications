FROM eclipse-temurin:21-jdk AS base

# Install openssl for cert generation
RUN apt-get update && apt-get install -y --no-install-recommends openssl unzip netcat-openbsd && rm -rf /var/lib/apt/lists/*

# Download and extract Ghidra
ARG GHIDRA_VERSION=12.0.4
ARG GHIDRA_DATE=20260303
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip
RUN curl -fsSL -o /tmp/ghidra.zip "$GHIDRA_URL" && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra && \
    rm /tmp/ghidra.zip

# Copy scripts and exploit source
COPY setup_pki.sh /opt/setup_pki.sh
COPY setup_server.sh /opt/setup_server.sh
COPY Setup.java /opt/Setup.java
RUN chmod +x /opt/setup_pki.sh /opt/setup_server.sh

# Create repo dir and seed user file
RUN mkdir -p /opt/repos && \
    printf 'admin:*:*:CN=admin,O=GhidraDemo,C=US\nanalyst:*:*:CN=analyst,O=GhidraDemo,C=US\n' > /opt/repos/users

# Compile all Java classes against Ghidra's JARs
RUN CP=""; \
    for jar in $(find /opt/ghidra/Ghidra -name "*.jar" \
      \( -path "*/GhidraServer/*" -o -path "*/FileSystem/*" -o -path "*/DB/*" \
         -o -path "*/Generic/*" -o -path "*/Utility/*" -o -path "*/Docking/*" \
         -o -path "*/Help/*" -o -path "*/Gui/*" \) | sort); do \
      CP="${CP:+$CP:}$jar"; \
    done; \
    javac -cp "$CP" -d /opt /opt/Setup.java

# Expose GhidraServer ports: registry, RMI SSL, block stream
EXPOSE 13100 13101 13102

ENV GHIDRA_HOME=/opt/ghidra \
    PKI_DIR=/opt/pki \
    REPOS_DIR=/opt/repos \
    JAVA_HOME=/opt/java/openjdk \
    PORT=13100

CMD ["/opt/setup_server.sh"]
