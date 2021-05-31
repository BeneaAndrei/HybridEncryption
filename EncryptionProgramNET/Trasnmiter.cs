﻿using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Security.Cryptography;


namespace EncryptionProgramNET
{
    class Trasnmiter
    {
        private RSAParameters privateKey;
        private RSAParameters publicKey;
        private RSAParameters reciverPublicKey;
        private byte[] originalData;
        private ASCIIEncoding ByteConverter = new ASCIIEncoding();
        Aes cipher;
        RSACryptoServiceProvider rsa;

        public Trasnmiter(string originalData, RSAParameters reciverPublicKey)
        {
            // Create byte arrays to hold orignial
            this.originalData = ByteConverter.GetBytes(originalData);

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

            this.reciverPublicKey = reciverPublicKey;


        }

        public RSAParameters GetPublicKey
        {
            get => publicKey;
        }

        public RSAParameters GetPrivateKey
        {
            get => privateKey;
        }

        private void EncryptPackage()
        {
            try
            {
                byte[] signedData;

                //Hash and singned the data
                signedData = HashAndSignBytes(originalData, privateKey);

                // Create new array in order to
                // Concat the signed and original data
                byte[] concatOriginalDataAndSignedData = ConcatArray(signedData, originalData);

                // Encrypt symetric the concatenated data of the original
                // And the signed data
                byte[] encrypredConcatData = EncryptCipher(cipher, concatOriginalDataAndSignedData);

                RSACryptoServiceProvider reciverRSA = new RSACryptoServiceProvider();
                reciverRSA.ImportParameters(reciverPublicKey);

                //Ecrypt the symetric Key with the Revicer's public Key
                byte[] encryptedSymetricKey = reciverRSA.Encrypt(cipher.Key, true);

                //Concatenates symetric key and concatenated data
                byte[] concatKeyAndData = new byte[encrypredConcatData.Length + encryptedSymetricKey.Length];

                encrypredConcatData.CopyTo(concatKeyAndData, 0);
                encryptedSymetricKey.CopyTo(concatKeyAndData, encrypredConcatData.Length);


            }
            catch (ArgumentNullException)
            {
                Console.WriteLine("The data was not signed or verified");
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
            byte[] concatArray = new byte[firstArray.Length + secondArray.Length];

            firstArray.CopyTo(concatArray, 0);
            secondArray.CopyTo(concatArray, firstArray.Length);

            return concatArray;
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






    }
}