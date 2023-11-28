using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        // Your string to encrypt
        Console.WriteLine("String for Encryption/Decryption: ");
        string originalString = Console.ReadLine();

        Console.WriteLine("Password: ");
        // Password to derive the key from
        string password = Console.ReadLine();

        Console.WriteLine("Salt (default: SaltForEncryption): ");
        // Password to derive the key from
        string salt = Console.ReadLine();
        if (string.IsNullOrWhiteSpace(salt)) salt = "SaltForEncryption";

        // Encrypt the string
        string encryptedString = EncryptString(originalString, password, salt);
        // Decrypt the string
        string decryptedString = DecryptString(originalString, password, salt);

        Console.WriteLine("Original String: " + originalString);
        Console.WriteLine("Encrypted String: " + encryptedString);
        Console.WriteLine("Decrypted String: " + decryptedString);

        Console.ReadLine();
    }

    static string EncryptString(string plainText, string password, string salt)
    {
        using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
        {
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes(salt));

            aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
            aesAlg.IV = key.GetBytes(aesAlg.BlockSize / 8);

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                }

                return Convert.ToBase64String(msEncrypt.ToArray());
            }
        }
    }

    static string DecryptString(string cipherText, string password, string salt)
    {
        using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
        {
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes(salt));

            aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
            aesAlg.IV = key.GetBytes(aesAlg.BlockSize / 8);

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText)))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }
    }
}
