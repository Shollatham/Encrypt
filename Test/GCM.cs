using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Test
{
    public static class GCM
    {
        private static string secretKey = "Special for DEV. In production it's going to be different";


        public static string ByteArrayToString(byte[] ba)
        {
            return Base32.Encode(ba);
        }

        public static byte[] StringToByteArray(string base32)
        {
            return Base32.Decode(base32);
        }
        public static byte[] encrypt(byte[] ciphertext)
        {
            SHA256CryptoServiceProvider sha = new SHA256CryptoServiceProvider();
            byte[] aesKeyData = sha.ComputeHash(Encoding.UTF8.GetBytes(secretKey)).Take(128 / 8).ToArray();
            byte[] IV = new byte[2];
            RandomNumberGenerator.Create().GetBytes(IV);

            var cipher = new GcmBlockCipher(new AesFastEngine());
            KeyParameter keyParameter = ParameterUtilities.CreateKeyParameter("AES", aesKeyData);
            ICipherParameters cipherParameters = new ParametersWithIV(keyParameter, IV);
            cipher.Init(true, cipherParameters);
            byte[] aad = Encoding.ASCII.GetBytes("test");
            cipher.ProcessAadBytes(aad, 0, aad.Length);
            
            byte[] output = new byte[cipher.GetOutputSize(ciphertext.Length)];
            int len = cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, output, 0);
            try
            {
                cipher.DoFinal(output, len);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            return IV.Concat(output).ToArray();
        }
        public static byte[] decrypt(byte[] inputBytes)
        {
            SHA256CryptoServiceProvider sha = new SHA256CryptoServiceProvider();
            byte[] aesKeyData = sha.ComputeHash(Encoding.UTF8.GetBytes(secretKey)).Take(128 / 8).ToArray();
            Byte[] IV = inputBytes.Take(2).ToArray();
            Byte[] outputBytes = inputBytes.Skip(2).ToArray();

            var cipher = new GcmBlockCipher(new AesFastEngine());
            KeyParameter keyParameter = ParameterUtilities.CreateKeyParameter("AES", aesKeyData);
            ICipherParameters cipherParameters = new ParametersWithIV(keyParameter, IV);
            cipher.Init(false, cipherParameters);
            byte[] aad = Encoding.ASCII.GetBytes("test");
            cipher.ProcessAadBytes(aad, 0, aad.Length);

            byte[] output = new byte[cipher.GetOutputSize(outputBytes.Length)];
            int len = cipher.ProcessBytes(outputBytes, 0, outputBytes.Length, output, 0);
            try
            {
                cipher.DoFinal(output, len);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            return output;
        }

        public static string encryptWithEncode(string input)
        {
            byte[] inputBytes = UTF8Encoding.UTF8.GetBytes(input);
            return ByteArrayToString(encrypt(inputBytes));
        }

        public static string decryptWithEncode(string input)
        {
            return Encoding.UTF8.GetString(decrypt(StringToByteArray(input)));
        }
    }
}
