package PGP_Reference_Application.PGPEncryption;

import PGP_Reference_Application.Keys.PGPEncryptionKeys;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;
import java.util.stream.Stream;

/**
 * Created by gsoto on 2/26/2017.
 */
public class PgpEncrypt {
    private PGPEncryptionKeys encryptionKeys;
    static private int symmetricAlgorithm;
    static private int compressionAlgorithm;
    static private int sigHashAlgorithmTag;

    private final int bufferSize = 0x10000;

    public PgpEncrypt(PGPEncryptionKeys encryptionKeys,
                      int symmetricAlgorithm,
                      int compressionAlgorithm,
                      int sigHashAlgorithmTag){

        if (encryptionKeys == null)
            throw new IllegalArgumentException("encryptionKeys is null");

        this.encryptionKeys = encryptionKeys;
        PgpEncrypt.symmetricAlgorithm = symmetricAlgorithm;
        PgpEncrypt.compressionAlgorithm = compressionAlgorithm;
        PgpEncrypt.sigHashAlgorithmTag = sigHashAlgorithmTag;
    }

    public void EncryptAndSign(OutputStream outputStream, String unencryptedFilename, boolean withArmor, boolean withIntegrityCheck)
            throws IOException, NoSuchProviderException {

        File unencryptedFile = new File(unencryptedFilename);

        if (outputStream == null)
            throw new IllegalArgumentException("outputStream is null");
        if (unencryptedFilename == null || unencryptedFilename.isEmpty())
            throw new IllegalArgumentException("Unencrypted filename is missing");
        if (!unencryptedFile.exists())
            throw new IllegalArgumentException("Unencrypted file is missing");

        if (withArmor) {
            outputStream = new ArmoredOutputStream(outputStream);
        }

        try {
            //SIGNATURE GENERATION OBJECTS
            PGPSignatureGenerator pgpSignatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(encryptionKeys.getPublicKey().getAlgorithm(), sigHashAlgorithmTag).setProvider("BC"));
            pgpSignatureGenerator.init(PGPSignature.BINARY_DOCUMENT, encryptionKeys.getPrivateKey());

            Iterator it = encryptionKeys.getPublicKey().getUserIDs();
            if (it.hasNext())
            {
                PGPSignatureSubpacketGenerator  signatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();

                signatureSubpacketGenerator.setSignerUserID(false, (String)it.next());
                pgpSignatureGenerator.setHashedSubpackets(signatureSubpacketGenerator.generate());
            }

            //ENCRYPTED GENERATOR OBJECTS
            PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(symmetricAlgorithm).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));

            encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKeys.getPublicKey()).setProvider("BC"));

            OutputStream encryptedOut = encryptedDataGenerator.open(outputStream, new byte[1 << 16]);

            //COMPRESSED GENERATOR OBJECTS
            /*PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(
                    PGPCompressedData.ZIP);*/
            PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(
                    compressionAlgorithm);

            OutputStream compressedOut = compressedDataGenerator.open(encryptedOut);

            BCPGOutputStream bcpgOutputStream = new BCPGOutputStream(compressedOut);

            pgpSignatureGenerator.generateOnePassVersion(false).encode(bcpgOutputStream);

            //LITERAL DATA GENERATOR OBJECTS
            PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();

            OutputStream literalOut = literalDataGenerator.open(bcpgOutputStream, PGPLiteralData.BINARY, unencryptedFile);
            FileInputStream in = new FileInputStream(unencryptedFile);

            int ch;
            while ((ch = in.read()) > 0)
            {
                literalOut.write(ch);
                pgpSignatureGenerator.update((byte)ch);
            }

            pgpSignatureGenerator.generate().encode(bcpgOutputStream);

            literalOut.close();
            bcpgOutputStream.close();
            in.close();

            compressedDataGenerator.close();

            encryptedOut.close();
            compressedOut.close();

            if (withArmor) {
                outputStream.close();
            }
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }
}
