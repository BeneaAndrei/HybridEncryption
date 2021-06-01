using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Security.Cryptography;

namespace EncryptionProgramNET
{
    class Receiver
    {
        private RSACryptoServiceProvider rsa;
        RSAParameters publicKey;
 

        public Receiver()
        {

            // Create a new isntance of the RSACryptoServiceProvider class
            // And automatically create a new key-pair.
            rsa = new RSACryptoServiceProvider();

            // You must pass false in order to export the public key for verficiation
            publicKey = rsa.ExportParameters(false);
        }

        public RSAParameters GetPublicKey
        {
            get => publicKey;
        }

        public void Decrypt(byte[] message, byte[] IV, RSAParameters transmiterPublicKey, int encryptDataLength, int signedDataLength)
        {
            try
            {
          
                //Separate the package in their 2 distinct form
                byte[] deconKeyAndData = message.Take(encryptDataLength).ToArray();
                byte[] deconSymetricKeyData = message.Skip(encryptDataLength).ToArray();

                //decrypts the symetric key using the private key
                deconSymetricKeyData = rsa.Decrypt(deconSymetricKeyData, true);
                
                //decrypts the boundle using the symetric key
                deconKeyAndData = DecryptCipher(IV, deconKeyAndData, deconSymetricKeyData);

                //Separates the initial mesage in the hased and the original message
                byte[] deconSignedData = deconKeyAndData.Take(signedDataLength).ToArray();
                byte[] deconOriginalData = deconKeyAndData.Skip(signedDataLength).ToArray();

                //verify the signed message 
                if (VerifySignedHash(deconOriginalData, deconSignedData, transmiterPublicKey))
                {
                    Console.WriteLine("The data was verified.");
                }
                else
                {
                    Console.WriteLine("The data does not match the signature");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        private static byte[] DecryptCipher(byte[] IV, byte[] encryptCipherText, byte[] key)
        {
            //creates a new symetric service
            Aes cipher = Aes.Create();
            
            cipher.Padding = PaddingMode.ISO10126;
            //Using the IV and the decrypted key
            cipher.IV = IV;
            cipher.Key = key;
            //decrypt the message
            ICryptoTransform decryptTransform = cipher.CreateDecryptor();
            return decryptTransform.TransformFinalBlock(encryptCipherText, 0, encryptCipherText.Length);

        }

        public static bool VerifySignedHash(byte[] DataToVerify, byte[] SignedData, RSAParameters Key)
        {
            try
            {
                // Create a new instance of RSACryptoServiceProvider using the
                // key from RSAParameters.
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

                RSAalg.ImportParameters(Key);

                // Verify the data using the signature.  Pass a new instance of SHA256
                // to specify the hashing algorithm.
                return RSAalg.VerifyData(DataToVerify, SHA256.Create(), SignedData);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return false;
            }
        }


    }
}
