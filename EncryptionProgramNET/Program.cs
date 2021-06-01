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
            
            Trasnmiter trasnmiter = new Trasnmiter();
            Reciver reciver = new Reciver();

            byte[] encryptedMessage = trasnmiter.EncryptPackage("mesaj",reciver.GetPublicKey);
            reciver.Decrypt(encryptedMessage, trasnmiter.GetVIVector,trasnmiter.GetPublicKey, trasnmiter.GetEncryptDataLength, trasnmiter.GetSignedDataLength);
            
        }

     


    }
}

