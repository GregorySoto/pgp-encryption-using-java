package PGP_Reference_Application.Keys;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.io.*;
import java.nio.file.Path;
import java.util.Iterator;

/**
 * Created by gsoto on 2/26/2017.
 */
public class PGPEncryptionKeys {
    private PGPPublicKey publicKey;
    private PGPPrivateKey privateKey;
    private PGPSecretKey secretKey;

    public PGPSecretKey getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(PGPSecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public PGPPublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PGPPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public PGPPrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PGPPrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public PGPEncryptionKeys(String publicKeyPath, String publicKeyUserId, String secretKeyPath,
                             String secretKeyUserId, String passPhrase)
            throws IOException, PGPException
    {
        File publicKeyFile = new File(publicKeyPath);
        File secretKeyFile = new File(secretKeyPath);

        if (!publicKeyFile.exists())
            throw new IllegalArgumentException("Public key file not found");
        if (!secretKeyFile.exists())
            throw new IllegalArgumentException("Secret key file not found");
        if (passPhrase == null || passPhrase.isEmpty())
            throw new IllegalArgumentException("passPhrase is empty");

        publicKey = readPublicKey(publicKeyPath, publicKeyUserId);

        secretKey = readSecretKey(secretKeyPath, secretKeyUserId);

        privateKey = readPrivateKey(passPhrase);
    }

    /**
     * A simple routine that opens a key ring file and returns the key that matches
     * the public User ID suitable for encryption.
     *
     * @param publicKeyPath filename containing the public key data
     * @param publicKeyUserId UserID of the key to use for encryption
     * @return the first public key found.
     * @throws IOException
     * @throws PGPException
     */
    static PGPPublicKey readPublicKey(String publicKeyPath, String publicKeyUserId)
            throws IOException, PGPException{
        InputStream keyIn = new BufferedInputStream(new FileInputStream(publicKeyPath));
        PGPPublicKey pubKey = readPublicKey(keyIn, publicKeyUserId);
        keyIn.close();
        return pubKey;
    }

    /**
     * A simple routine that iterates through the keys in a key ring file
     * and selects the key, which can be used for encryption, based on a public key UserID if it exists.
     *
     * @param input data stream containing the public key data
     * @param publicKeyUserId UserID of the key to use for encryption
     * @return the first public key found.
     * @throws IOException
     * @throws PGPException
     */
    private static PGPPublicKey readPublicKey(InputStream input, String publicKeyUserId) throws IOException, PGPException
    {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext())
        {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext())
            {
                PGPPublicKey key = (PGPPublicKey)keyIter.next();

                if (key.isEncryptionKey())
                {
                    Iterator userIdIter = key.getUserIDs();
                    while(userIdIter.hasNext()){
                        String userId = (String)userIdIter.next();
                        if (userId.equals(publicKeyUserId))
                            return key;
                    }
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    /**
     * A simple routine that opens a key ring file and returns the key that matches
     * the secret User ID suitable for signing.
     *
     * @param secretKeyPath filename containing the secret key data
     * @param secretKeyUserId UserID of the key to use for signing
     * @return the first public key found.
     * @throws IOException
     * @throws PGPException
     */
    static PGPSecretKey readSecretKey(String secretKeyPath, String secretKeyUserId) throws IOException, PGPException
    {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(secretKeyPath));
        PGPSecretKey secKey = readSecretKey(keyIn, secretKeyUserId);
        keyIn.close();
        return secKey;
    }

    /**
     * A simple routine that opens a key ring file and loads the first available key
     * suitable for signature generation.
     *
     * @param input stream to read the secret key ring collection from.
     * @param secretKeyUserId UserID of the key to use for signing
     * @return a secret key.
     * @throws IOException on a problem with using the input stream.
     * @throws PGPException if there is an issue parsing the input stream.
     */
    static PGPSecretKey readSecretKey(InputStream input, String secretKeyUserId) throws IOException, PGPException
    {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        Iterator keyRingIter = pgpSec.getKeyRings();
        while (keyRingIter.hasNext())
        {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();

            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext())
            {
                PGPSecretKey key = (PGPSecretKey)keyIter.next();

                if (key.isSigningKey())
                {
                    Iterator userIdIter = key.getUserIDs();
                    while(userIdIter.hasNext()){
                        String userId = (String)userIdIter.next();
                        if (userId.equals(secretKeyUserId))
                            return key;
                    }
                }
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }

    /**
     * A simple routine that extracts the private key from the secret key previously set
     * @param passPhrase password used to access the private key
     * @return a private key
     * @throws PGPException
     */
    private PGPPrivateKey readPrivateKey(String passPhrase) throws PGPException{
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passPhrase.toCharArray()));

        if (privateKey != null)
            return privateKey;
        throw new IllegalArgumentException("No private key found in secret key");
    }
}
