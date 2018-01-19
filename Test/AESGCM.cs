using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
namespace Test
{

    public static class AESGCM
    {
        private static readonly SecureRandom Random = new SecureRandom();

        //Preconfigured Encryption Parameters
        public static readonly int KeyBitSize = 128;
        public static readonly int TagBitSize = 96;
        public static readonly int IVBitSize = 16;

        //Preconfigured Password Key Derivation Parameters
        public static readonly int SaltBitSize = 128;
        public static readonly int Iterations = 10000;

        private static byte[] GetSecretKey(string secretKey)
        {
            SHA256CryptoServiceProvider sha = new SHA256CryptoServiceProvider();
            return sha.ComputeHash(Encoding.UTF8.GetBytes(secretKey)).Take(KeyBitSize / 8).ToArray();
        }

        public static string SimpleEncrypt(string secretMessage, string secretKey, string aad = null)
        {
            if (string.IsNullOrEmpty(secretMessage))
                throw new ArgumentException("Secret Message Required!", "secretMessage");
            if (string.IsNullOrEmpty(secretKey))
                throw new ArgumentException("Secret Key Required!", "secretKey");

            var nonSecretPayload = Encoding.ASCII.GetBytes(aad);
            var plainText = Encoding.UTF8.GetBytes(secretMessage);
            var cipherText = SimpleEncrypt(plainText, GetSecretKey(secretKey), nonSecretPayload);
            return Base32.Encode(cipherText);
        }
        
        public static string SimpleDecrypt(string encryptedMessage, string secretKey, string aad = null)
        {
            if (string.IsNullOrEmpty(encryptedMessage))
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");
            if (string.IsNullOrEmpty(secretKey))
                throw new ArgumentException("Secret Key Required!", "secretKey");

            var cipherText = Base32.Decode(encryptedMessage);
            var nonSecretPayload = Encoding.ASCII.GetBytes(aad);
            var plainText = SimpleDecrypt(cipherText, GetSecretKey(secretKey), nonSecretPayload);
            return plainText == null ? null : Encoding.UTF8.GetString(plainText);
        }

        public static byte[] SimpleEncrypt(byte[] secretMessage, byte[] key, byte[] nonSecretPayload = null)
        {
            //User Error Checks
            if (key == null || key.Length != KeyBitSize / 8)
                throw new ArgumentException(String.Format("Key needs to be {0} bit!", KeyBitSize), "key");

            if (secretMessage == null || secretMessage.Length == 0)
                throw new ArgumentException("Secret Message Required!", "secretMessage");

            //Non-secret Payload Optional
            nonSecretPayload = nonSecretPayload ?? new byte[] { };

            //Using random nonce large enough not to repeat
            var IV = new byte[IVBitSize / 8];
            Random.NextBytes(IV, 0, IV.Length);

            var cipher = new GcmBlockCipher(new AesFastEngine());
            var parameters = new AeadParameters(new KeyParameter(key), TagBitSize, IV, nonSecretPayload);
            cipher.Init(true, parameters);

            //Generate Cipher Text With Auth Tag
            var cipherText = new byte[cipher.GetOutputSize(secretMessage.Length)];
            var len = cipher.ProcessBytes(secretMessage, 0, secretMessage.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);

            //Assemble Message
            using (var combinedStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(combinedStream))
                {
                    binaryWriter.Write(IV);
                    binaryWriter.Write(cipherText);
                }
                return combinedStream.ToArray();
            }
        }

        public static byte[] SimpleDecrypt(byte[] encryptedMessage, byte[] key, byte[] nonSecretPayload = null)
        {
            //User Error Checks
            if (key == null || key.Length != KeyBitSize / 8)
                throw new ArgumentException(String.Format("Key needs to be {0} bit!", KeyBitSize), "key");

            if (encryptedMessage == null || encryptedMessage.Length == 0)
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");

            byte[] IV = encryptedMessage.Take(2).ToArray();
            encryptedMessage = encryptedMessage.Skip(2).ToArray();
            using (var cipherStream = new MemoryStream(encryptedMessage))
            using (var cipherReader = new BinaryReader(cipherStream))
            {
                var cipher = new GcmBlockCipher(new AesFastEngine());
                var parameters = new AeadParameters(new KeyParameter(key), TagBitSize, IV, nonSecretPayload);
                cipher.Init(false, parameters);

                //Decrypt Cipher Text
                var cipherText = cipherReader.ReadBytes(encryptedMessage.Length);
                var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];

                try
                {
                    var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
                    cipher.DoFinal(plainText, len);

                }
                catch (InvalidCipherTextException)
                {
                    //Return null if it doesn't authenticate
                    return null;
                }

                return plainText;
            }
        }
    }
}