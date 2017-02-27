package PGP_Reference_Application.PGPDecryption;

import jdk.internal.util.xml.impl.Input;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.NoSuchProviderException;
import java.util.Iterator;

/**
 * Created by gsoto on 2/26/2017.
 */
public class PGPDecrypt {
    private final int bufferSize = 0x10000;

    public static void Decrypt(String inputFilename,
                               String secretKeyFilename,
                               String passPhrase,
                               String outputFilename,
                               String publicKeyFilename)
            throws IOException, NoSuchProviderException
    {
        File encryptedFile = new File(inputFilename);
        File secretKeyFile = new File(secretKeyFilename);
        File publicKeyFile = new File(publicKeyFilename);

        if (inputFilename == null || inputFilename.isEmpty())
            throw new IllegalArgumentException("Encrypted filename is missing");
        if (secretKeyFilename == null || secretKeyFilename.isEmpty())
            throw new IllegalArgumentException("Secret key filename is missing");
        if (passPhrase == null || passPhrase.isEmpty())
            throw new IllegalArgumentException("Passphrase is missing");
        if (outputFilename == null || outputFilename.isEmpty())
            throw new IllegalArgumentException("Output filename is missing");
        if (publicKeyFilename == null || publicKeyFilename.isEmpty())
            throw new IllegalArgumentException("Public key filename is missing");

        if (!encryptedFile.exists())
            throw new IllegalArgumentException("Unencrypted file is missing");
        if (!secretKeyFile.exists())
            throw new IllegalArgumentException("Secret key file is missing");
        if (!publicKeyFile.exists())
            throw new IllegalArgumentException("Public key file is missing");

        InputStream in = new BufferedInputStream(new FileInputStream(inputFilename));
        InputStream privateKeyIn = new BufferedInputStream(new FileInputStream(secretKeyFilename));
        InputStream publicKeyIn = new BufferedInputStream(new FileInputStream(publicKeyFilename));
        decryptFile(in, privateKeyIn, passPhrase.toCharArray(), outputFilename, publicKeyIn);
        publicKeyIn.close();
        privateKeyIn.close();
        in.close();
    }

    private static void decryptFile(
            InputStream in,
            InputStream privateKeyIn,
            char[]      passwd,
            String      outputFilename,
            InputStream publicKeyIn)
            throws IOException, NoSuchProviderException
    {
        boolean deleteOutputFile = false;

        in = PGPUtil.getDecoderStream(in);

        try
        {
            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
            PGPEncryptedDataList enc;

            Object                  o = pgpF.nextObject();

            // the first object might be a PGP marker packet.
            if (o instanceof PGPEncryptedDataList)
            {
                enc = (PGPEncryptedDataList)o;
            }
            else
            {
                enc = (PGPEncryptedDataList)pgpF.nextObject();
            }

            // find the secret key
            Iterator it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(privateKeyIn), new JcaKeyFingerprintCalculator());

            while (sKey == null && it.hasNext())
            {
                pbe = (PGPPublicKeyEncryptedData)it.next();
                sKey = findSecretKey(pgpSec, pbe.getKeyID(), passwd);
                if (sKey != null) break;
            }

            if (sKey == null)
            {
                throw new IllegalArgumentException("secret key for message not found.");
            }

            JcaPGPObjectFactory plainFact = null;
            InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
            plainFact = new JcaPGPObjectFactory(clear);

            Object message = plainFact.nextObject();

            if (message instanceof PGPCompressedData){
                PGPCompressedData cData = (PGPCompressedData)message;

                JcaPGPObjectFactory of = null;

                InputStream compressedStream = new BufferedInputStream(cData.getDataStream());
                of = new JcaPGPObjectFactory(compressedStream);

                message = of.nextObject();

                if (message instanceof PGPOnePassSignatureList){
                    PGPOnePassSignature onePassSignature = ((PGPOnePassSignatureList)message).get(0);

                    PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                            PGPUtil.getDecoderStream(publicKeyIn), new JcaKeyFingerprintCalculator());

                    //USE THE BELOW TO CHECK FOR A FAILING SIGNATURE VERIFICATION
                    //THE CERTIFICATE MATCHING THE KEY ID MUST BE IN THE PUBLIC KEY RING.
                    //long fakeKeyId = 3008998260528343108L;
                    //PGPPublicKey publicKey = pgpPub.getPublicKey(fakeKeyId);

                    PGPPublicKey publicKey = pgpPub.getPublicKey(onePassSignature.getKeyID());

                    onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);

                    message = of.nextObject();
                    PGPLiteralData ld = (PGPLiteralData)message;

                    //THE OUTPUT FILENAME WILL BE BASED ON THE INPUT PARAMETER VALUE TO THIS METHOD.
                    //IF YOU WANT TO KEEP THE ORIGINAL FILENAME, UNCOMMENT THE FOLLOWING LINE.
                    /*if (ld.getFileName() != null && !ld.getFileName().isEmpty())
                        outputFilename = ld.getFileName();*/

                    try(OutputStream outputStream = new BufferedOutputStream(new FileOutputStream(outputFilename))){
                        InputStream dIn = ld.getInputStream();

                        int ch;
                        while ((ch = dIn.read()) >= 0){
                            onePassSignature.update(((byte)ch));
                            outputStream.write((byte)ch);
                        }
                        outputStream.close();
                    }

                    PGPSignatureList pgpSignatureList = (PGPSignatureList)of.nextObject();
                    PGPSignature pgpSignature = pgpSignatureList.get(0);

                    if(onePassSignature.verify(pgpSignature)){
                        System.out.println("Signature verified");
                    }
                    else{
                        System.out.println("Signature verification failed");

                        //YOU MAY OPT TO DELETE THE OUTPUT FILE IN THE EVENT THAT VERIFICATION FAILS.
                        //FILE DELETION HAPPENS FURTHER DOWN IN THIS METHOD
                        //AN ALTERNATIVE IS TO LOG THESE VERIFICATION FAILURE MESSAGES, BUT KEEP THE OUTPUT FILE FOR FURTHER ANALYSIS
                        //deleteOutputFile = true;
                    }

                }
                else if (message instanceof PGPLiteralData)
                {
                    PGPLiteralData ld = (PGPLiteralData)message;

                    writeLiteralData(ld, outputFilename);
                }
            }
            else if (message instanceof PGPLiteralData)
            {
                PGPLiteralData ld = (PGPLiteralData)message;

                writeLiteralData(ld, outputFilename);
            }
            else if (message instanceof PGPOnePassSignatureList)
            {
                throw new PGPException("encrypted message contains a signed message - not literal data.");
            }
            else
            {
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }

            if (pbe.isIntegrityProtected())
            {
                if (!pbe.verify())
                {
                    System.err.println("message failed integrity check");

                    //YOU MAY OPT TO DELETE THE OUTPUT FILE IN THE EVENT THAT THE INTEGRITY PROTECTION CHECK FAILS.
                    //FILE DELETION HAPPENS FURTHER DOWN IN THIS METHOD.
                    //AN ALTERNATIVE IS TO LOG THESE VERIFICATION FAILURE MESSAGES, BUT KEEP THE OUTPUT FILE FOR FURTHER ANALYSIS
                    //deleteOutputFile = true;
                }
                else
                {
                    System.err.println("message integrity check passed");
                }
            }
            else
            {
                System.err.println("no message integrity check");
            }
        }
        catch (PGPException e)
        {
            System.err.println(e);
            if (e.getUnderlyingException() != null)
            {
                e.getUnderlyingException().printStackTrace();
            }
        }

        //DELETE THE FILE IN THE EVENT THAT SIGNATURE VERIFICATION OR INTEGRITY PROTECTION CHECK HAS FAILED.
        //FILE DELETION IS SET TO FALSE BY DEFAULT.
        if (deleteOutputFile){
            File output = new File(outputFilename);
            output.delete();
        }
    }

    private static void writeLiteralData(PGPLiteralData literalData, String outputFilename){
        /*if (ld.getFileName().length() != 0)
                    outputFilename = ld.getFileName();*/

        InputStream unc = literalData.getInputStream();
        try {
            OutputStream fOut = new BufferedOutputStream(new FileOutputStream(outputFilename));

            Streams.pipeAll(unc, fOut);

            fOut.close();
        }
        catch(FileNotFoundException ex){
            System.out.println(ex.getMessage());
        }
        catch(IOException ex){
            System.out.println(ex.getMessage());
        }
    }

    private static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyId, char[] pass)
            throws PGPException, NoSuchProviderException{
        PGPSecretKey pgpSecretKey = pgpSec.getSecretKey(keyId);

        if (pgpSecretKey == null) return null;

        return pgpSecretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
    }
}
