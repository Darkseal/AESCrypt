# AESCrypt
Yet Another AES-Rijndael ASP.NET C# implementation package with advanced configuration settings - by https://www.ryadel.com/

# Introduction
The AES 256 / Rijndael encryption standard had a lot of ASP.NET C# implementations within the past few years: projects like BouncyCastle, SharpAESCrypt and CryptoN, just to name a few of them, are all quite simple to use and 100% working. So, why should we publish "yet another" AES 256 C# implementation class?

The answer is basically the same we usually do whenever we end up reinventing the weel, just like we did when we wrote our C# random password generator, the PDF-to-TXT and PDF-to-HTML converter and many other helper classes: we needed to do something that couldn't be done with the existing alternatives. This time we weren't looking for a "simple" implementation to handle the standard AES encryption/decryption tasks in the seamless possible way: conversely, we needed to configure some specific aspects of the AES cryptographic algorythm, such as the BlockSize, the Cipher mode, the Crypt algorithm, the Password Hashing algorithm (if any), the number of password iterations (if any), the Initialization Vector (IV), the Key Length (whenever we need it fixed), the Salt, the Padding mode, and so on.

In order to fullfill this tasks we came up with the following package, which we called AESCrypt - pretty original, isn't it? The usage is still fairly simple and very similar to the other AES-based packages - as long as you don't need to mess up with all these settings and are ok with the industry-standard defaults - yet it also has a decent (and further expandable) option class that can be configured to handle most of the encryption details.

# Usage Samples
Let's start with a couple encrypt & decrypt code samples to see how it can be used in a typical back-end scenario:

```csharp
// text to encrypt
var text = "Hello world!";

// passPhrase (32 bit length for AES256)
var passPhrase = "12345678901234567890123456789012";

// Initialization Vector (16 bit length)
var iv = "1234567890123456";

// Encrypt & Decrypt (with standard settings)
var encryptedText = new AESCrypt(passPhrase, iv).Encrypt();
var sourceText = new AESCrypt(passPhrase, iv).Decrypt(encryptedText);

// Encrypt & Decrypt (with advanced settings)
var opts = new AESCryptOptions() {
        PasswordHash = AESPasswordHash.SHA1,
        PasswordHashIterations = 2,
        PasswordHashSalt = "23$9uBsDjf8",
        PaddingMode = PaddingMode.Zeroes,
        MinSaltLength = 4,
        MaxSaltLength = 8
    };
var encryptedText = new AESCrypt(passPhrase, iv, opts).Encrypt();
var sourceText = new AESCrypt(passPhrase, iv, opts).Decrypt(encryptedText);
```

As we can see, we can use either the simple mode - which uses the most common AES standards - or an advanced mode if we need more granular control.

# Online Resources
* Author's official website: https://www.ryadel.com/
* Package explanation and usage samples: https://www.ryadel.com/en/aes-256-class-asp-net-c-sharp-custom-options-settings-hash-padding-mode-keylength-cipher-salt-iv-rijndael/
