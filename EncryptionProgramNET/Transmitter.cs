using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Security.Cryptography;


namespace EncryptionProgramNET
{
    class Transmitter
    {
        private RSAParameters privateKey;
        private RSAParameters publicKey;
        private byte[] encrypredConcatData;
        private byte[] signedData;
        private ASCIIEncoding ByteConverter = new ASCIIEncoding();
        Aes cipher;
        RSACryptoServiceProvider rsa;

        public Transmitter()
        {
            


            // Create a new isntance of the RSACryptoServiceProvider class
            // And automatically create a new key-pair.
            rsa = new RSACryptoServiceProvider();

            // Export the key information to an RSAParameters object.
            // You must pass true to export the private key for signing.
            // However, you do not need to export the private key
            // for verification.
            privateKey = rsa.ExportParameters(true);

            // You must pass false in order to export the public key for verficiation
            publicKey = rsa.ExportParameters(false);

            // Create a new isntance of a Symetric Encryption system
            cipher = CreateCipher();

        }

        #region Getters
        public RSAParameters GetPublicKey
        {
            get => publicKey;
        }

        public RSAParameters GetPrivateKey
        {
            get => privateKey;
        }

        public byte[] GetVIVector
        {
            get => cipher.IV;
        }

        public int GetEncryptDataLength
        {
            get => encrypredConcatData.Length;
        }

        public int GetSignedDataLength
        {
            get => signedData.Length;
        }

        #endregion

        public byte[] EncryptPackage(string message, RSAParameters reciverPublicKey)
        {
            try
            {
                //Converts the message to bytes
                byte[] originalData = ByteConverter.GetBytes(message); 
               

                //Hash and singned the data
                signedData = HashAndSignBytes(originalData, privateKey);

                // Create new array in order to
                // Concat the signed and original data
                byte[] concatOriginalDataAndSignedData = ConcatArray(signedData, originalData);

                // Encrypt symetric the concatenated data of the original
                // And the signed data
                encrypredConcatData = EncryptCipher(cipher, concatOriginalDataAndSignedData);
                
                //Creates a new RSA service using the public key of the reciver
                RSACryptoServiceProvider reciverRSA = new RSACryptoServiceProvider();
                reciverRSA.ImportParameters(reciverPublicKey);

                //Ecrypt the symetric Key with the Revicer's public Key
                byte[] encryptedSymetricKey = reciverRSA.Encrypt(cipher.Key, true);

                //Concatenates symetric key and concatenated data
                byte[] concatKeyAndData = ConcatArray(encrypredConcatData, encryptedSymetricKey);

                return concatKeyAndData;


            }
            catch (ArgumentNullException)
            {
                Console.WriteLine("The data was not signed or verified");
                return null;
            }

        }

      
        private static byte[] HashAndSignBytes(byte[] DataToSign, RSAParameters Key)
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

        
        private byte[] ConcatArray(byte[] firstArray, byte[] secondArray)
        {
            //Creates a new array using the length of the two arrays that were passed
            byte[] concatArray = new byte[firstArray.Length + secondArray.Length];

            //Coppy the arrays in order to be concatenated
            firstArray.CopyTo(concatArray, 0);
            secondArray.CopyTo(concatArray, firstArray.Length);

            //Return the concatenated array
            return concatArray;
        }

        private static Aes CreateCipher()
        {
            //Generates a new symetric service
            Aes cipher = Aes.Create();
            //setting padding
            cipher.Padding = PaddingMode.ISO10126;
            //generate the symetrical key
            cipher.GenerateKey();
            //generate the IV vector
            cipher.GenerateIV();

            //returns the service
            return cipher;
        }

        private static byte[] EncryptCipher(Aes cipher, byte[] ConcatText)
        {
            //Symetrical encrypts the message
            ICryptoTransform cryptTransform = cipher.CreateEncryptor();
            return cryptTransform.TransformFinalBlock(ConcatText, 0, ConcatText.Length);

        }

    }
}
