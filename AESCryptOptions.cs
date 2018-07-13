/////////////////////////////////////////////////////////////////////////////////////////////////////
// AESCrypt - Symmetric key encryption and decryption using AES/Rijndael algorythm (128, 192 and 256)
// https://www.ryadel.com/ , 2016
/////////////////////////////////////////////////////////////////////////////////////////////////////
using System.Security.Cryptography;

namespace Ryadel.Components.Security
{
    public class AESCryptOptions
    {
        #region Private members
        // Do not allow salt to be longer than 255 bytes, because we have only
        // 1 byte to store its length. 
        private static int MAX_ALLOWED_SALT_LEN = 255;

        // Do not allow salt to be smaller than 4 bytes, because we use the first
        // 4 bytes of salt to store its length. 
        private static int MIN_ALLOWED_SALT_LEN = 4;

        // Random salt value will be between 4 and 8 bytes long.
        private static int DEFAULT_MIN_SALT_LEN = MIN_ALLOWED_SALT_LEN;
        private static int DEFAULT_MAX_SALT_LEN = 8;

        // These members will be used to perform encryption and decryption.
        private ICryptoTransform encryptor = null;
        private ICryptoTransform decryptor = null;

        #endregion

        #region Constructor
        public AESCryptOptions()
        {
            PasswordHash = AESPasswordHash.SHA1;
            PasswordHashIterations = 1;
            MinSaltLength = 0;
            MaxSaltLength = 0;
            FixedKeySize = null;
            PaddingMode = PaddingMode.PKCS7;
        }
        #endregion

        #region Properties
        /// <summary>
        /// Key Size: this is typically 128, 192 or 256, depending on the password length in bit (16, 24 or 32 respectively).
        /// Default is NULL, meaning that it will be calculated on-the-fly using the password bit length. 
        /// </summary>
        public int? FixedKeySize { get; set; }

        /// <summary>
        /// Password hashing mode: None, MD5 or SHA1.
        /// SHA1 is the recommended mode for most scenarios.
        /// </summary>
        public AESPasswordHash PasswordHash { get; set; }

        /// <summary>
        /// Password iterations - not used when [PasswordHash] is set to [AESPasswordHash.None]
        /// </summary>
        public int PasswordHashIterations { get; set; }

        /// <summary>
        ///  Minimum Salt Length: must be equal or smaller than MaxSaltLength.
        ///  Default is 0.
        /// </summary>
        public int MinSaltLength { get; set; }

        /// <summary>
        ///  Maximum Salt Length: must be equal or greater than MinSaltLength.
        ///  Default is 0, meaning that no salt will be used.
        /// </summary>
        public int MaxSaltLength { get; set; }

        /// <summary>
        /// Salt value used for password hashing during key generation.
        /// NOTE: This is not the same as the salt we will use during encryption.
        /// This parameter can be any string (set it to NULL for no password hash salt): default is NULL.
        /// </summary>
        public string PasswordHashSalt { get; set; }

        /// <summary>
        /// Sets the Padding Mode (default is PaddingMode.PKCS7)
        /// </summary>
        public PaddingMode PaddingMode { get; set; }
        #endregion

    }
}
