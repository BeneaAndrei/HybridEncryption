using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Security.Cryptography;

namespace EncryptionProgramNET
{
    class Reciver
    {
        private RSACryptoServiceProvider rsa;
        RSAParameters publicKey;
 

        public Reciver()
        {
            rsa = new RSACryptoServiceProvider();
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
          
                byte[] deconKeyAndData = message.Take(encryptDataLength).ToArray();
                byte[] deconSymetricKeyData = message.Skip(encryptDataLength).ToArray();

                deconSymetricKeyData = rsa.Decrypt(deconSymetricKeyData, true);

                deconKeyAndData = DecryptCipher(IV, deconKeyAndData, deconSymetricKeyData);

                byte[] deconSignedData = deconKeyAndData.Take(signedDataLength).ToArray();
                byte[] deconOriginalData = deconKeyAndData.Skip(signedDataLength).ToArray();

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
            Aes cipher = Aes.Create();
            cipher.Padding = PaddingMode.ISO10126;
            cipher.IV = IV;
            cipher.Key = key;
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
