using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Security.Cryptography;

namespace EncryptionProgramNET
{
    class Reciver
    {
        RSACryptoServiceProvider rsa;
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

        
    }
}
