using System;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace EncryptionProgramNET
{
    class Program
    {

        public void Reciver(string dataString)
        {
            try
            {
                // Create a UnicodeEncoder to convert between byte array and string
                ASCIIEncoding ByteConverter = new ASCIIEncoding();

                // Create byte arrays to hold orignial, encrypted and decrypted data
                byte[] originalData = ByteConverter.GetBytes(dataString);
                byte[] signedData;

                // Create a new isntance of the RSACryptoServiceProvider class
                // And automatically create a new key-pair.
                RSACryptoServiceProvider aliceRSA = new RSACryptoServiceProvider();

                // Export the key information to an RSAParameters object.
                // You must pass true to export the private key for signing.
                // However, you do not need to export the private key
                // for verification.
                RSAParameters privateKey = aliceRSA.ExportParameters(true);

                // You must pass false in order to export the public key for verficiation
                RSAParameters publicKey = aliceRSA.ExportParameters(false);

                //Hash and singned the data
                signedData = HashAndSignBytes(originalData, privateKey);

                // Create new array in order to
                // Concat the signed and original data
                byte[] concatOriginalDataAndSignedData = ConcatArray(signedData, originalData);

                // Create a new isntance of a Symetric Encryption system
                Aes cipher = CreateCipher();

                // Encrypt symetric the concatenated data of the original
                // And the signed data
                byte[] encrypredConcatData = EncryptCipher(cipher, concatOriginalDataAndSignedData);

                      RSACryptoServiceProvider bobRLSA = new RSACryptoServiceProvider();
                //Encrypt symetric key
                byte[] keyEncrypt = bobRLSA.Encrypt(cipher.Key, true);
                //Concatenate symetric key and concatenated data
                byte[] concatKeyAndData = new byte[encrypredConcatData.Length + keyEncrypt.Length];

                encrypredConcatData.CopyTo(concatKeyAndData, 0);
                keyEncrypt.CopyTo(concatKeyAndData, encrypredConcatData.Length);








            }
            catch (ArgumentNullException)
            {
                Console.WriteLine("The data was not signed or verified");
            }

        }

        static void Main()
        {
            try
            {
                //// Create a UnicodeEncoder to convert between byte array and string.
                //ASCIIEncoding ByteConverter = new ASCIIEncoding();

                //string dataString = "Data to Sign";

                //// Create byte arrays to hold original, encrypted, and decrypted data.
                //byte[] originalData = ByteConverter.GetBytes(dataString);
                //byte[] signedData;
                

                //// Create a new instance of the RSACryptoServiceProvider class
                //// and automatically create a new key-pair.
                //RSACryptoServiceProvider aliceRLSA = new RSACryptoServiceProvider();

                //// Export the key information to an RSAParameters object.
                //// You must pass true to export the private key for signing.
                //// However, you do not need to export the private key
                //// for verification.
                //RSAParameters Key = aliceRLSA.ExportParameters(true);
                //RSAParameters publicKey = aliceRLSA.ExportParameters(false);

                //// Hash and sign the data.
                //signedData = HashAndSignBytes(originalData, Key);

                //// Create new array in order to
                //// Concat the signed and original data
                //byte[] concatData = new byte[originalData.Length + signedData.Length];
                
                //// Coppy the signed and original data to the array
                //signedData.CopyTo(concatData, 0);
                //originalData.CopyTo(concatData, signedData.Length);

                //Aes cipher = CreateCipher();
                ////Encrypted concatenated mesage + signature
                //byte[] encrypredConcatData = EncryptCipher(cipher, concatData);


                //Create second RSA Crypto service
                RSACryptoServiceProvider bobRLSA = new RSACryptoServiceProvider();
                //Encrypt symetric key
                byte[] keyEncrypt = bobRLSA.Encrypt(cipher.Key, true);
                //Concatenate symetric key and concatenated data
                byte[] concatKeyAndData = new byte[encrypredConcatData.Length + keyEncrypt.Length];

                encrypredConcatData.CopyTo(concatKeyAndData, 0);
                keyEncrypt.CopyTo(concatKeyAndData, encrypredConcatData.Length);

                ///////////////////////////////////////////////////////////////////

                byte[] deconKeyAndData = concatKeyAndData.Take(encrypredConcatData.Length).ToArray();
                byte[] deconSymetricKeyData = concatKeyAndData.Skip(encrypredConcatData.Length).ToArray();

                deconSymetricKeyData = bobRLSA.Decrypt(deconSymetricKeyData,true);

                deconKeyAndData = DecryptCipher(cipher, deconKeyAndData, deconSymetricKeyData);

                byte[] deconSignedData = deconKeyAndData.Take(signedData.Length).ToArray();
                byte[] deconOriginalData = deconKeyAndData.Skip(signedData.Length).ToArray();


                //string keyEncryptionString = Convert.ToBase64String(keyEncrypt);
                //Console.WriteLine(keyEncryptionString);

                if(VerifySignedHash(deconOriginalData,deconSignedData, publicKey))
                {
                    Console.WriteLine("The data was verified.");
                }
                else
                {
                    Console.WriteLine("The data does not match the signature.");
                }


            }
            catch (ArgumentNullException)
            {
                Console.WriteLine("The data was not signed or verified");
            }
        }

     


        public static byte[] HashAndSignBytes(byte[] DataToSign, RSAParameters Key)
        {
            try
            {
                // Create a new instance of RSACryptoServiceProvider using the
                // key from RSAParameters.
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

                RSAalg.ImportParameters(Key);

                // Hash and sign the data. Pass a new instance of SHA256
                // to specify the hashing algorithm.
                return RSAalg.SignData(DataToSign, SHA256.Create());
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }
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

        private static Aes CreateCipher()
        {
            Aes cipher = Aes.Create();

            cipher.Padding = PaddingMode.ISO10126;
            cipher.GenerateKey();
            cipher.GenerateIV();

            return cipher;
        }
        private static byte[] EncryptCipher(Aes cipher, byte[] ConcatText)
        {
            ICryptoTransform cryptTransform = cipher.CreateEncryptor();
            return cryptTransform.TransformFinalBlock(ConcatText, 0, ConcatText.Length);
          
        }

        private static byte[] DecryptCipher(Aes cipher, byte[] encryptCipherText, byte[] key)
        {
            cipher.Key = key;
            ICryptoTransform decryptTransform = cipher.CreateDecryptor();
           return decryptTransform.TransformFinalBlock(encryptCipherText, 0, encryptCipherText.Length);
            
        }

        private byte[] ConcatArray(byte[] firstArray, byte[] secondArray)
        { 
            byte[] concatArray = new byte[firstArray.Length + secondArray.Length];

            firstArray.CopyTo(concatArray, 0);
            secondArray.CopyTo(concatArray, firstArray.Length);

            return concatArray;
        }

    }
}

