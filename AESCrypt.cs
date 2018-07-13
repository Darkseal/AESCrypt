/////////////////////////////////////////////////////////////////////////////////////////////////////
// AESCrypt - Symmetric key encryption and decryption using AES/Rijndael algorythm (128, 192 and 256)
// https://www.ryadel.com/ , 2016
/////////////////////////////////////////////////////////////////////////////////////////////////////
using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.ComponentModel;

namespace Ryadel.Components.Security
{
    /// <summary>
    /// This class uses a symmetric key algorithm (AES) to encrypt and decrypt data. As long as it is initialized with the same constructor
    /// parameters, the class will use the same key. Before performing encryption, the class can prepend random bytes to plain text and generate different
    /// encrypted values from the same plain text, encryption key, initialization vector, and other parameters. This class is thread-safe.
    /// </summary>
    public class AESCrypt
    {
        #region Private members
        // These members will be used to perform encryption and decryption.
        private ICryptoTransform encryptor = null;
        private ICryptoTransform decryptor = null;

        private AESCryptOptions Options = null;

        #endregion

        #region Constructors
        /// <summary>
        /// Use this constructor to perform encryption/decryption with the following options:
        /// - 128/192/256-bit key (depending on passPhrase length in bits)
        /// - SHA-1 password hashing algorithm with 4-to-8 byte long password hash salt and 1 password iteration
        /// - hashing without salt
        /// - no initialization vector
        /// - electronic codebook (ECB) mode
        /// </summary>
        /// <param name="passPhrase">
        /// Passphrase (in string format) from which a pseudo-random password will be derived. The derived password will be used to generate the encryption key.
        /// </param>
        /// <remarks>
        /// This constructor is NOT recommended because it does not use initialization vector and uses the ECB cipher mode, which is less secure than the CBC mode.
        /// </remarks>
        public AESCrypt(string passPhrase) :
            this(passPhrase, null)
        {
        }

        /// <summary>
        /// Use this constructor to perform encryption/decryption with the following options:
        /// - 128/192/256-bit key (depending on passPhrase length in bits)
        /// - SHA-1 password hashing algorithm with 4-to-8 byte long password hash salt and 1 password iteration
        /// - hashing without salt
        /// - cipher block chaining (CBC) mode
        /// </summary>
        /// <param name="passPhrase">
        /// Passphrase (in string format) from which a pseudo-random password will be derived. The derived password will be used to generate the encryption key.
        /// </param>
        /// <param name="initVector">
        /// Initialization vector (IV). This value is required to encrypt the first block of plaintext data. IV must be exactly 16 ASCII characters long.
        /// </param>
        public AESCrypt(string passPhrase,
                                string initVector) :
            this(passPhrase, initVector, new AESCryptOptions())
        {
        }

        /// <summary>
        /// Use this constructor to perform encryption/decryption with custom options.
        /// See AESCryptOptions documentation for details.
        /// </summary>
        /// <param name="passPhrase">
        /// Passphrase (in string format) from which a pseudo-random password will be derived. The derived password will be used to generate the encryption key.
        /// </param>
        /// <param name="initVector">
        /// Initialization vector (IV). This value is required to encrypt the first block of plaintext data. IV must be exactly 16 ASCII characters long.
        /// </param>
        /// <param name="options">
        /// A set of customized (or default) options to use for the encryption/decryption: see AESCryptOptions documentation for details.
        /// </param>
        public AESCrypt(string passPhrase, string initVector, AESCryptOptions options)
        {
            // store the options object locally.
            this.Options = options;

            // Checks for the correct (or null) size of cryptographic key.
            if (Options.FixedKeySize.HasValue
                && Options.FixedKeySize != 128
                && Options.FixedKeySize != 192
                && Options.FixedKeySize != 256)
                throw new NotSupportedException("ERROR: options.FixedKeySize must be NULL (for auto-detect) or have a value of 128, 192 or 256");

            // Initialization vector converted to a byte array.
            byte[] initVectorBytes = null;

            // Salt used for password hashing (to generate the key, not during
            // encryption) converted to a byte array.
            byte[] saltValueBytes = null;

            // Get bytes of initialization vector.
            if (initVector == null) initVectorBytes = new byte[0];
            else initVectorBytes = Encoding.UTF8.GetBytes(initVector);

            // Gets the KeySize
            int keySize = (Options.FixedKeySize.HasValue)
                ? Options.FixedKeySize.Value
                : GetAESKeySize(passPhrase);

            // Get bytes of password (hashing it or not)
            byte[] keyBytes = null;
            if (Options.PasswordHash == AESPasswordHash.None)
            {
                // Convert passPhrase to a byte array
                keyBytes = System.Text.Encoding.UTF8.GetBytes(passPhrase);
            }
            else
            {
                // Get bytes of password hash salt
                if (Options.PasswordHashSalt == null) saltValueBytes = new byte[0];
                else saltValueBytes = Encoding.UTF8.GetBytes(options.PasswordHashSalt);

                // Generate password, which will be used to derive the key.
                PasswordDeriveBytes password = new PasswordDeriveBytes(
                                                           passPhrase,
                                                           saltValueBytes,
                                                           Options.PasswordHash.ToString().ToUpper().Replace("-", ""),
                                                           Options.PasswordHashIterations);

                // Convert key to a byte array adjusting the size from bits to bytes.
                keyBytes = password.GetBytes(keySize / 8);
            }

            // Initialize AES key object.
            AesManaged symmetricKey = new AesManaged();

            // Sets the padding mode
            symmetricKey.Padding = Options.PaddingMode;

            // Use the unsafe ECB cypher mode (not recommended) if no IV has been provided, otherwise use the more secure CBC mode.
            symmetricKey.Mode = (initVectorBytes.Length == 0) 
                ? CipherMode.ECB 
                : CipherMode.CBC;

            // Create the encryptor and decryptor objects, which we will use for cryptographic operations.
            encryptor = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes);
            decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes);
        }
        #endregion

        #region Encryption routines
        /// <summary>
        /// Encrypts a string value generating a base64-encoded string.
        /// </summary>
        /// <param name="plainText">
        /// Plain text string to be encrypted.
        /// </param>
        /// <returns>
        /// Cipher text formatted as a base64-encoded string.
        /// </returns>
        public string Encrypt(string plainText)
        {
            return Encrypt(Encoding.UTF8.GetBytes(plainText));
        }

        /// <summary>
        /// Encrypts a byte array generating a base64-encoded string.
        /// </summary>
        /// <param name="plainTextBytes">
        /// Plain text bytes to be encrypted.
        /// </param>
        /// <returns>
        /// Cipher text formatted as a base64-encoded string.
        /// </returns>
        public string Encrypt(byte[] plainTextBytes)
        {
            return Convert.ToBase64String(EncryptToBytes(plainTextBytes));
        }

        /// <summary>
        /// Encrypts a string value generating a byte array of cipher text.
        /// </summary>
        /// <param name="plainText">
        /// Plain text string to be encrypted.
        /// </param>
        /// <returns>
        /// Cipher text formatted as a byte array.
        /// </returns>
        public byte[] EncryptToBytes(string plainText)
        {
            return EncryptToBytes(Encoding.UTF8.GetBytes(plainText));
        }

        /// <summary>
        /// Encrypts a byte array generating a byte array of cipher text.
        /// </summary>
        /// <param name="plainTextBytes">
        /// Plain text bytes to be encrypted.
        /// </param>
        /// <returns>
        /// Cipher text formatted as a byte array.
        /// </returns>
        public byte[] EncryptToBytes(byte[] plainTextBytes)
        {
            // Add salt at the beginning of the plain text bytes (if needed).
            byte[] plainTextBytesWithSalt = (UseSalt()) ? AddSalt(plainTextBytes) : plainTextBytes;

            byte[] cipherTextBytes = null;

            // Let's make cryptographic operations thread-safe.
            lock (this)
            {
                // Encryption will be performed using memory stream.
                using (MemoryStream memoryStream = new MemoryStream())
                {

                    // To perform encryption, we must use the Write mode.
                    using (CryptoStream cryptoStream = new CryptoStream(
                                                       memoryStream,
                                                       encryptor,
                                                        CryptoStreamMode.Write))
                    {

                        // Start encrypting data.
                        cryptoStream.Write(plainTextBytesWithSalt, 0, plainTextBytesWithSalt.Length);
                        // Finish the encryption operation.
                        cryptoStream.FlushFinalBlock();
                        // Move encrypted data from memory into a byte array.
                        cipherTextBytes = memoryStream.ToArray();
                        cryptoStream.Close();
                    }
                    memoryStream.Close();
                }
                // Return encrypted data.
                return cipherTextBytes;
            }
        }
        #endregion

        #region Decryption routines
        /// <summary>
        /// Decrypts a base64-encoded cipher text value generating a string result.
        /// </summary>
        /// <param name="cipherText">
        /// Base64-encoded cipher text string to be decrypted.
        /// </param>
        /// <returns>
        /// Decrypted string value.
        /// </returns>
        public string Decrypt(string cipherText)
        {
            return Decrypt(Convert.FromBase64String(cipherText));
        }

        /// <summary>
        /// Decrypts a byte array containing cipher text value and generates a
        /// string result.
        /// </summary>
        /// <param name="cipherTextBytes">
        /// Byte array containing encrypted data.
        /// </param>
        /// <returns>
        /// Decrypted string value.
        /// </returns>
        public string Decrypt(byte[] cipherTextBytes)
        {
            return Encoding.UTF8.GetString(DecryptToBytes(cipherTextBytes));
        }

        /// <summary>
        /// Decrypts a base64-encoded cipher text value and generates a byte array
        /// of plain text data.
        /// </summary>
        /// <param name="cipherText">
        /// Base64-encoded cipher text string to be decrypted.
        /// </param>
        /// <returns>
        /// Byte array containing decrypted value.
        /// </returns>
        public byte[] DecryptToBytes(string cipherText)
        {
            return DecryptToBytes(Convert.FromBase64String(cipherText));
        }

        /// <summary>
        /// Decrypts a base64-encoded cipher text value and generates a byte array
        /// of plain text data.
        /// </summary>
        /// <param name="cipherTextBytes">
        /// Byte array containing encrypted data.
        /// </param>
        /// <returns>
        /// Byte array containing decrypted value.
        /// </returns>
        public byte[] DecryptToBytes(byte[] cipherTextBytes)
        {
            byte[] decryptedBytes = null;
            byte[] plainTextBytes = null;
            int decryptedByteCount = 0;
            int saltLen = 0;

            // Since we do not know how big decrypted value will be, use the same
            // size as cipher text. Cipher text is always longer than plain text
            // (in block cipher encryption), so we will just use the number of
            // decrypted data byte after we know how big it is.
            decryptedBytes = new byte[cipherTextBytes.Length];

            // Let's make cryptographic operations thread-safe.
            lock (this)
            {
                using (MemoryStream memoryStream = new MemoryStream(cipherTextBytes))
                {
                    // To perform decryption, we must use the Read mode.
                    using (CryptoStream cryptoStream = new CryptoStream(
                                                       memoryStream,
                                                       decryptor,
                                                       CryptoStreamMode.Read))
                    {

                        // Decrypting data and get the count of plain text bytes.
                        decryptedByteCount = cryptoStream.Read(decryptedBytes,
                                                                0,
                                                                decryptedBytes.Length);
                        cryptoStream.Close();
                    }
                    memoryStream.Close();
                }
            }

            // If we are using salt, get its length from the first 4 bytes of plain text data.
            if (UseSalt())
            {
                saltLen = (decryptedBytes[0] & 0x03) |
                            (decryptedBytes[1] & 0x0c) |
                            (decryptedBytes[2] & 0x30) |
                            (decryptedBytes[3] & 0xc0);
            }

            // Allocate the byte array to hold the original plain text (without salt).
            plainTextBytes = new byte[decryptedByteCount - saltLen];

            // Copy original plain text discarding the salt value if needed.
            Array.Copy(decryptedBytes, saltLen, plainTextBytes,
                        0, decryptedByteCount - saltLen);

            // Return original plain text value.
            return plainTextBytes;
        }
        #endregion

        #region Helper functions
        /// <summary>
        /// Gets the KeySize by the password length in bytes.
        /// </summary>
        /// <param name="p"></param>
        /// <returns></returns>
        public static int GetAESKeySize(string passPhrase)
        {
            switch (passPhrase.Length)
            {
                case 16:
                    return 128;
                case 24:
                    return 192;
                case 32:
                    return 256;
                default:
                    throw new NotSupportedException("ERROR: AES Password must be of 16, 24 or 32 bits length!");
            }
        }

        /// <summary>
        /// Checks if salt must be used or not for the encryption/decryption.
        /// </summary>
        /// <returns></returns>
        private bool UseSalt()
        {
            // Use salt if the max salt value is greater than 0 and equal or greater than min salt length.
            return (Options.MaxSaltLength > 0 && Options.MaxSaltLength >= Options.MinSaltLength);
        }


        /// <summary>
        /// Adds an array of randomly generated bytes at the beginning of the
        /// array holding original plain text value.
        /// </summary>
        /// <param name="plainTextBytes">
        /// Byte array containing original plain text value.
        /// </param>
        /// <returns>
        /// Either original array of plain text bytes (if salt is not used) or a
        /// modified array containing a randomly generated salt added at the 
        /// beginning of the plain text bytes. 
        /// </returns>
        private byte[] AddSalt(byte[] plainTextBytes)
        {
            // Additional check
            if (!UseSalt()) return plainTextBytes;

            // Generate the salt.
            byte[] saltBytes = GenerateSalt(Options.MinSaltLength, Options.MaxSaltLength);

            // Allocate array which will hold salt and plain text bytes.
            byte[] plainTextBytesWithSalt = new byte[plainTextBytes.Length + saltBytes.Length];
            // First, copy salt bytes.
            Array.Copy(saltBytes, plainTextBytesWithSalt, saltBytes.Length);

            // Append plain text bytes to the salt value.
            Array.Copy(plainTextBytes, 0,
                        plainTextBytesWithSalt, saltBytes.Length,
                        plainTextBytes.Length);

            return plainTextBytesWithSalt;
        }

        /// <summary>
        /// Generates an array holding cryptographically strong bytes.
        /// </summary>
        /// <returns>
        /// Array of randomly generated bytes.
        /// </returns>
        /// <remarks>
        /// Salt size will be defined at random or exactly as specified by the
        /// minSlatLen and maxSaltLen parameters passed to the object constructor.
        /// The first four bytes of the salt array will contain the salt length
        /// split into four two-bit pieces.
        /// </remarks>
        private byte[] GenerateSalt(int minSaltLen, int maxSaltLen)
        {
            // We don't have the length, yet.
            int saltLen = 0;

            // If min and max salt values are the same, it should not be random.
            if (minSaltLen == maxSaltLen) saltLen = minSaltLen;
            // Use random number generator to calculate salt length.
            else
                saltLen = GenerateRandomNumber(minSaltLen, maxSaltLen);

            // Allocate byte array to hold our salt.
            byte[] salt = new byte[saltLen];

            // Populate salt with cryptographically strong bytes.
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

            rng.GetNonZeroBytes(salt);

            // Split salt length (always one byte) into four two-bit pieces and
            // store these pieces in the first four bytes of the salt array.
            salt[0] = (byte)((salt[0] & 0xfc) | (saltLen & 0x03));
            salt[1] = (byte)((salt[1] & 0xf3) | (saltLen & 0x0c));
            salt[2] = (byte)((salt[2] & 0xcf) | (saltLen & 0x30));
            salt[3] = (byte)((salt[3] & 0x3f) | (saltLen & 0xc0));

            return salt;
        }

        /// <summary>
        /// Generates random integer.
        /// </summary>
        /// <param name="minValue">
        /// Min value (inclusive).
        /// </param>
        /// <param name="maxValue">
        /// Max value (inclusive).
        /// </param>
        /// <returns>
        /// Random integer value between the min and max values (inclusive).
        /// </returns>
        /// <remarks>
        /// This methods overcomes the limitations of .NET Framework's Random
        /// class, which - when initialized multiple times within a very short
        /// period of time - can generate the same "random" number.
        /// </remarks>
        private int GenerateRandomNumber(int minValue, int maxValue)
        {
            // We will make up an integer seed from 4 bytes of this array.
            byte[] randomBytes = new byte[4];

            // Generate 4 random bytes.
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(randomBytes);

            // Convert four random bytes into a positive integer value.
            int seed = ((randomBytes[0] & 0x7f) << 24) |
                        (randomBytes[1] << 16) |
                        (randomBytes[2] << 8) |
                        (randomBytes[3]);

            // Now, this looks more like real randomization.
            Random random = new Random(seed);

            // Calculate a random number.
            return random.Next(minValue, maxValue + 1);
        }
        #endregion
    }
}
