package PGP_Reference_Application;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.NoSuchFileException;
import java.security.NoSuchProviderException;
import java.security.Security;

import PGP_Reference_Application.Keys.PGPEncryptionKeys;
import PGP_Reference_Application.PGPDecryption.PGPDecrypt;
import PGP_Reference_Application.PGPEncryption.PgpEncrypt;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPUtil;

/**
 * Created by gsoto on 2/25/2017.
 */
public class Program {

    private static String _keyRingHome = "C:\\keys\\Kleopatra";

    private static String publicKeyRingFilename = "pubring.gpg";

    private static String secretKeyRingFilename = "secring.gpg";

    private static String secretKeyRingPassphrase = "open1234";

    private static String filePath = "C:\\\\Keys\\\\Files";

    private static String originalInputFile = "PlainText.txt";

    private static String encryptedFile = "JavaEncryptedData1.txt";

    private static String outputFile = "JavaOriginal.txt";

    // Used for signing
    private static int sigHashAlgorithm = PGPUtil.SHA1;

    private static String signatureKeyUserId = "Gregory Soto1 <sotogregory@gmail.com>";

    private static boolean withIntegrityCheck = true;

    private static boolean withArmor = true;

    // Used for compression
    private static int compressionAlgorithm = PGPCompressedData.ZIP;

    // Used for encryption
    private static int symmetricAlgorithm = PGPEncryptedData.AES_128;

    private static String publicKeyEncryptionUserId = "Gregory Soto1 <sotogregory@gmail.com>";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        Program objPgp = new Program();
        /*if ((Debugger.IsAttached != true)) {
            _keyRingHome = Environment.GetEnvironmentVariable("GNUPGHOME");
        }*/

        try{

            objPgp.encryption();
            //objPgp.decryption();
        }
        catch(Exception ex){
            System.out.println("Something went wrong");
            System.out.println(ex.getMessage());
        }

        System.out.println("Done");

    }

    public final void encryption() {
        System.out.println("Encrypting");

        try{
            System.out.println(filePath + "\\" + encryptedFile);

            PGPEncryptionKeys encryptionKeys = new PGPEncryptionKeys(
                    _keyRingHome + "\\" + publicKeyRingFilename, publicKeyEncryptionUserId, _keyRingHome + "\\" +
                    secretKeyRingFilename, signatureKeyUserId, secretKeyRingPassphrase);

            PgpEncrypt encrypter = new PgpEncrypt(encryptionKeys, symmetricAlgorithm, compressionAlgorithm, sigHashAlgorithm);

            try(OutputStream outputStream = new BufferedOutputStream(new FileOutputStream(filePath + "\\" + encryptedFile))){
                encrypter.EncryptAndSign(outputStream, filePath + "\\" + originalInputFile, withArmor, withIntegrityCheck);
            }
        }
        catch (NoSuchProviderException ex){
            System.out.println(ex.getMessage());
        }
        catch (PGPException ex){
            System.out.println(ex.getMessage());
        }
        catch (IOException ex){
            System.out.println(ex.getMessage());
        }

        System.out.println("Encryption done");
    }

    public final void decryption() {
        System.out.println("Decrypting");

        try {
            PGPDecrypt.Decrypt(filePath + "\\" + encryptedFile, _keyRingHome + "\\" + secretKeyRingFilename, secretKeyRingPassphrase, filePath + "\\" + outputFile, _keyRingHome + "\\" + publicKeyRingFilename);
        }
        catch(NoSuchProviderException ex){
            System.out.println(ex.getMessage());
        }
        catch (IOException ex){
            System.out.println(ex.getMessage());
        }

        System.out.println("Decryption Done");
    }
}
