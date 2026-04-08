import java.io.*;
import java.rmi.registry.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import javax.net.ssl.*;
import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.security.auth.*;
import javax.security.auth.callback.*;

import ghidra.framework.remote.*;

/**
 * Setup: Authenticate as admin with LEGITIMATE credentials and create an
 * admin-only repository. The analyst user is intentionally excluded from
 * the ACL so we can demonstrate the impact of the exploit later.
 */
public class Setup {

    public static void main(String[] args) throws Exception {
        String host     = "localhost";
        int    port     = 13100;
        String adminKey = "/opt/pki/admin.p12";
        String caCert   = "/opt/pki/ca.crt";
        String repoName = "SecretAnalysis";
        String password = "changeit";

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--host":      host     = args[++i]; break;
                case "--port":      port     = Integer.parseInt(args[++i]); break;
                case "--admin-key": adminKey = args[++i]; break;
                case "--ca-cert":   caCert   = args[++i]; break;
                case "--repo":      repoName = args[++i]; break;
                case "--password":  password = args[++i]; break;
            }
        }

        System.out.println("=".repeat(72));
        System.out.println(" GhidraServer Setup — Creating Admin-Only Repository");
        System.out.println("=".repeat(72));
        System.out.println();

        // ── Load certificates ──────────────────────────────────────────────
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        X509Certificate ca;
        try (FileInputStream f = new FileInputStream(caCert)) {
            ca = (X509Certificate) cf.generateCertificate(f);
        }

        KeyStore adminKS = KeyStore.getInstance("PKCS12");
        try (FileInputStream f = new FileInputStream(adminKey)) {
            adminKS.load(f, password.toCharArray());
        }
        String alias = adminKS.aliases().nextElement();
        X509Certificate adminCert = (X509Certificate) adminKS.getCertificate(alias);
        PrivateKey adminPrivKey = (PrivateKey) adminKS.getKey(alias, password.toCharArray());

        System.out.println("  Connecting to: " + host + ":" + port);
        System.out.println("  Admin cert:    " + adminCert.getSubjectX500Principal());
        System.out.println();

        // ── mTLS with admin's cert ─────────────────────────────────────────
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(adminKS, password.toCharArray());

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("ca", ca);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslCtx = SSLContext.getInstance("TLS");
        sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        SSLContext.setDefault(sslCtx);

        // ── Authenticate as admin (LEGITIMATE — signs with private key) ────
        SslRMIClientSocketFactory sslFactory = new SslRMIClientSocketFactory();
        Registry registry = LocateRegistry.getRegistry(host, port, sslFactory);
        GhidraServerHandle handle =
            (GhidraServerHandle) registry.lookup(GhidraServerHandle.BIND_NAME);

        Callback[] callbacks = handle.getAuthenticationCallbacks();
        SignatureCallback sigCb = null;
        for (Callback cb : callbacks) {
            if (cb instanceof SignatureCallback) sigCb = (SignatureCallback) cb;
        }
        if (sigCb == null) throw new RuntimeException("No SignatureCallback");

        // Sign the challenge token with admin's private key
        byte[] token = sigCb.getToken();
        Signature sig = Signature.getInstance(adminCert.getSigAlgName());
        sig.initSign(adminPrivKey);
        sig.update(token);
        byte[] signature = sig.sign();

        sigCb.sign(new X509Certificate[]{ adminCert, ca }, signature);

        Subject subject = new Subject();
        subject.getPrincipals().add(new GhidraPrincipal("setup"));
        RemoteRepositoryServerHandle server = handle.getRepositoryServer(subject, callbacks);

        System.out.println("[1] Authenticated as: " + server.getUser());

        // ── Create repository ──────────────────────────────────────────────
        System.out.println("[2] Creating repository '" + repoName + "'...");
        RepositoryHandle repo = server.createRepository(repoName);
        System.out.println("    Created: " + repo.getName());

        // ── Restrict ACL: admin-only, analyst explicitly excluded ──────────
        System.out.println("[3] Setting ACL to admin-only (analyst excluded)...");
        User[] adminOnlyAcl = new User[]{ new User("admin", User.ADMIN) };
        repo.setUserList(adminOnlyAcl, false /* no anonymous access */);

        User[] finalAcl = repo.getUserList();
        System.out.println("    Final ACL:");
        for (User u : finalAcl) {
            System.out.println("      " + u);
        }

        System.out.println();
        System.out.println("=".repeat(72));
        System.out.println(" SETUP COMPLETE");
        System.out.println(" Repository '" + repoName + "' is restricted to admin only.");
        System.out.println(" The analyst user has zero visibility into this repository.");
        System.out.println("=".repeat(72));
    }
}
