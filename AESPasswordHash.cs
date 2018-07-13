/////////////////////////////////////////////////////////////////////////////////////////////////////
// AESCrypt - Symmetric key encryption and decryption using AES/Rijndael algorythm (128, 192 and 256)
// https://www.ryadel.com/ , 2016
/////////////////////////////////////////////////////////////////////////////////////////////////////
namespace Ryadel.Components.Security
{
    /// <summary>
    /// AES Password Hash: set "None" for no hashing.
    /// </summary>
    public enum AESPasswordHash : int
    {
        None = 0,
        MD5 = 1,
        SHA1 = 2
    }
}
