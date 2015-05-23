package io.netty.handler.ssl;

import android.util.Base64;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufInputStream;
import io.netty.util.internal.EmptyArrays;

public class AndroidSslClientContext extends JdkSslContext {

    private final SSLContext ctx;

    byte[] readPem(InputStream certificateStream) throws IOException {
        byte[] der;
        BufferedReader reader = null;

        try {
            reader = new BufferedReader(new InputStreamReader(certificateStream));

            StringBuilder pem = new StringBuilder();
            String line;
            while((line = reader.readLine()) != null) {
                if(!line.startsWith("--")){
                    pem.append(line);
                }
            }

            der = Base64.decode(pem.toString(), Base64.DEFAULT);
        } finally {
            if(reader != null) {
                reader.close();
            }
        }
        return der;
    }

    /**
     * Build a {@link javax.net.ssl.KeyManagerFactory} based upon a key algorithm, key file, key file password,
     * and a certificate chain.
     * @param certChainFile a X.509 certificate chain file in PEM format
     * @param keyAlgorithm the standard name of the requested algorithm. See the Java Secure Socket Extension
     * Reference Guide for information about standard algorithm names.
     * @param keyFile a PKCS#8 private key file in PEM format
     * @param keyPassword the password of the {@code keyFile}.
     *                    {@code null} if it's not password-protected.
     * @param kmf The existing {@link javax.net.ssl.KeyManagerFactory} that will be used if not {@code null}
     * @return A {@link javax.net.ssl.KeyManagerFactory} based upon a key algorithm, key file, key file password,
     * and a certificate chain.
     */
    public static KeyManagerFactory buildKeyManagerFactory(File certChainFile,
                                                           String keyAlgorithm, File keyFile, String keyPassword,
                                                           KeyManagerFactory kmf)
            throws KeyStoreException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeySpecException, InvalidAlgorithmParameterException, IOException,
            CertificateException, KeyException, UnrecoverableKeyException {
        // Store key in a bouncy castle.
        KeyStore ks = KeyStore.getInstance("BKS");
        ks.load(null, null);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        KeyFactory rsaKF = KeyFactory.getInstance("RSA");
        KeyFactory dsaKF = KeyFactory.getInstance("DSA");

        ByteBuf encodedKeyBuf = PemReader.readPrivateKey(keyFile);
        byte[] encodedKey = new byte[encodedKeyBuf.readableBytes()];
        encodedKeyBuf.readBytes(encodedKey).release();

        char[] keyPasswordChars = keyPassword == null ? EmptyArrays.EMPTY_CHARS : keyPassword.toCharArray();
        PKCS8EncodedKeySpec encodedKeySpec = generateKeySpec(keyPasswordChars, encodedKey);

        PrivateKey key;
        try {
            key = rsaKF.generatePrivate(encodedKeySpec);
        } catch (InvalidKeySpecException ignore) {
            key = dsaKF.generatePrivate(encodedKeySpec);
        }

        List<Certificate> certChain = new ArrayList<Certificate>();
        ByteBuf[] certs = PemReader.readCertificates(certChainFile);
        try {
            for (ByteBuf buf: certs) {
                certChain.add(cf.generateCertificate(new ByteBufInputStream(buf)));
            }
        } finally {
            for (ByteBuf buf: certs) {
                buf.release();
            }
        }

        ks.setKeyEntry("key", key, keyPasswordChars, certChain.toArray(new java.security.cert.Certificate[certChain.size()]));

        // Set up key manager factory to use our key store
        if (kmf == null) {
            kmf = KeyManagerFactory.getInstance(keyAlgorithm);
        }
        kmf.init(ks, keyPasswordChars);

        return kmf;
    }

    public AndroidSslClientContext(File caFile,
                                   File clientCertificate, File clientKey) {
        super(null, IdentityCipherSuiteFilter.INSTANCE, ApplicationProtocolConfig.DISABLED, false);

        try {
            // Load CA cert
            byte[] der = readPem(new FileInputStream(caFile));
            ByteArrayInputStream derInputStream = new ByteArrayInputStream(der);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certificateFactory
                    .generateCertificate(derInputStream);
            String alias = cert.getSubjectX500Principal().getName();

            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null);
            trustStore.setCertificateEntry(alias, cert);

            String androidX509 = "X509";
            KeyManagerFactory kmf = buildKeyManagerFactory(clientCertificate, androidX509, clientKey, null, null);

            KeyManager[] keyManagers = kmf.getKeyManagers();

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
            tmf.init(trustStore);
            TrustManager[] trustManagers = tmf.getTrustManagers();

            ctx = SSLContext.getInstance("TLS");
            ctx.init(keyManagers, trustManagers, null);
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public SSLContext context() {
        return ctx;
    }

    @Override
    public boolean isClient() {
        return true;
    }
}
