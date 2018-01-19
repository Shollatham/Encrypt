using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Security.Cryptography;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

public static class EncryptionHelper
{
    private static byte[] keyAndIvBytes;
    private static string secretKey = "Special for DEV. In production it's going to be different";

    static EncryptionHelper()
    {
        SHA256CryptoServiceProvider sha = new SHA256CryptoServiceProvider();
        keyAndIvBytes = sha.ComputeHash(UTF8Encoding.UTF8.GetBytes(secretKey)).Take(128 / 8).ToArray();
   
    }

    public static string ByteArrayToString(byte[] ba)
    {
        return Base32.Encode(ba);
        //return BitConverter.ToString(ba).Replace("-", "");
    }

    public static byte[] StringToByteArray(string base32)
    {
        return Base32.Decode(base32);
        //return Enumerable.Range(0, hex.Length)
        //                 .Where(x => x % 2 == 0)
        //                 .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
        //                 .ToArray();
    }

    public static string DecodeAndDecrypt(string cipherText)
    {
        string DecodeAndDecrypt = AesDecrypt(StringToByteArray(cipherText));
        return (DecodeAndDecrypt);
    }

    public static string EncryptAndEncode(string plaintext)
    {
        return ByteArrayToString(AesEncrypt(plaintext));
    }

    public static string AesDecrypt(Byte[] inputBytes)
    {
        Byte[] iv = inputBytes.Take(2).ToArray();
        Byte[] outputBytes = inputBytes.Skip(2).ToArray();

        string plaintext = string.Empty;
        var crypto = GetCryptoAlgorithm();
        crypto.Key = keyAndIvBytes;
        //crypto.IV = iv;

        using (MemoryStream memoryStream = new MemoryStream(outputBytes))
        {
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, crypto.CreateDecryptor(), CryptoStreamMode.Read))
            {
                using (StreamReader srDecrypt = new StreamReader(cryptoStream))
                {
                    plaintext = srDecrypt.ReadToEnd();
                }
            }
        }

        return plaintext;
    }

    public static byte[] AesEncrypt(string inputText)
    {
        byte[] inputBytes = UTF8Encoding.UTF8.GetBytes(inputText);
        byte[] iv = new byte[2];
        RandomNumberGenerator.Create().GetBytes(iv);
        byte[] result = null;
        using (var aes = GetCryptoAlgorithm())
        using (MemoryStream memoryStream = new MemoryStream())
        {
            using (IAuthenticatedCryptoTransform encryptor = aes.CreateAuthenticatedEncryptor(keyAndIvBytes, iv))
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
            {
                cryptoStream.Write(inputBytes, 0, inputBytes.Length);
                cryptoStream.FlushFinalBlock();

                result = memoryStream.ToArray().Concat(encryptor.GetTag()).ToArray();
            }
        }

        return result;
    }


    private static AuthenticatedAesCng GetCryptoAlgorithm()
    {
        GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine());
        AuthenticatedAesCng algorithm = new AuthenticatedAesCng();
        algorithm.CngMode = CngChainingMode.Gcm;
        algorithm.Padding = PaddingMode.None;
        algorithm.AuthenticatedData = Encoding.ASCII.GetBytes("test");
        algorithm.KeySize = 128;
        algorithm.BlockSize = 128;
        algorithm.TagSize = 96;
        return algorithm;
    }
}