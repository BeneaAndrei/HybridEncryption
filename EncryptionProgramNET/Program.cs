using System;
using System.Security.Cryptography;
using System.Text;
using System.Linq;


namespace EncryptionProgramNET
{
    class Program
    {

  

        static void Main()
        {
            //Created and instance of the Transmiter class
            //in order to acces the public key
            Transmitter trasnmiter = new Transmitter();

            //Created and instance of the Reciver class
            //in order to acces the public key
            Receiver reciver = new Receiver();
            
            //Encrypt the message and return it
            byte[] encryptedMessage = trasnmiter.EncryptPackage("mesaj",reciver.GetPublicKey);

            //Decrypt and verify the message
            reciver.Decrypt(encryptedMessage, trasnmiter.GetVIVector,trasnmiter.GetPublicKey, trasnmiter.GetEncryptDataLength, trasnmiter.GetSignedDataLength);
            
        }

     


    }
}

