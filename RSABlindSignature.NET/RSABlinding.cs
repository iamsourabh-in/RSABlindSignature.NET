using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace RSABlindSignature.NET
{
    public class RSABlinding
    {
        public static (RSAParameters, RSAParameters) GenerateKeyPair(int keySize)
        {
            RSAParameters publicKey = new RSAParameters();
            RSAParameters privateKey = new RSAParameters();

            // Create a new RSA instance with the specified key size
            using (RSA rsa = RSA.Create(keySize))
            {
                // Export the public key parameters (only public information)
                publicKey = rsa.ExportParameters(false);

                // Export the private key parameters (includes private key information)
                privateKey = rsa.ExportParameters(true);
            }
            return (publicKey, privateKey);
        }

        /// <summary>
        /// Blinds a message (represented as a BigInteger) using the public key.
        /// The method computes: blinded = m * r^e mod n, where r is a random blinding factor.
        /// </summary>
        /// <param name="message">The message as a string.</param>
        /// <param name="publicKey">The RSA public key.</param>
        /// <returns>The blinded message as a BigInteger.</returns>
        public static (BigInteger, BigInteger) Blind(string message, RSAParameters publicKey)
        {
            BigInteger m = StringToBigInteger(message);
            BigInteger n = BytesToBigInteger(publicKey.Modulus);
            BigInteger e = BytesToBigInteger(publicKey.Exponent);

            // Generate a random blinding factor r such that 1 < r < n and gcd(r, n) == 1.
            BigInteger r = GenerateRandomBigInteger(n);

            // Compute r^e mod n.
            BigInteger rPowE = BigInteger.ModPow(r, e, n);
            // Blind the message: blinded = message * r^e mod n.
            BigInteger blinded = (m * rPowE) % n;
            return (blinded, r);
        }

        /// <summary>
        /// Signs the blinded message using the private key.
        /// Computes: signature = (blindedMessage)^d mod n.
        /// </summary>
        /// <param name="blindedMessage">The blinded message.</param>
        /// <returns>The blind signature as a BigInteger.</returns>
        public static BigInteger Sign(BigInteger blindedMessage, RSAParameters privateKey)
        {
            BigInteger n = BytesToBigInteger(privateKey.Modulus);
            BigInteger d = BytesToBigInteger(privateKey.D);
            BigInteger signature = BigInteger.ModPow(blindedMessage, d, n);
            return signature;
        }

        /// <summary>
        /// Unblinds the signature using the stored blinding factor.
        /// Computes: unblindedSignature = signature * (r^-1) mod n.
        /// </summary>
        /// <param name="signature">The blind signature.</param>
        /// <param name="blindingFactor">The blinding factor used during blinding.</param>
        /// <returns>The unblinded signature as a BigInteger.</returns>
        public static BigInteger Unblind(BigInteger signature, BigInteger blindingFactor, RSAParameters publicKey)
        {
            BigInteger n = BytesToBigInteger(publicKey.Modulus);
            BigInteger rInv = ModInverse(blindingFactor, n);
            BigInteger unblinded = (signature * rInv) % n;
            return unblinded;
        }

        /// <summary>
        /// Verifies the unblinded signature by checking if: (signature)^e mod n == original message.
        /// </summary>
        /// <param name="message">The original message string.</param>
        /// <param name="signature">The unblinded signature as a BigInteger.</param>
        /// <returns>True if the signature is valid; otherwise, false.</returns>
        public static bool Verify(string message, BigInteger signature, RSAParameters publicKey)
        {
            BigInteger m = StringToBigInteger(message);
            BigInteger n = BytesToBigInteger(publicKey.Modulus);
            BigInteger e = BytesToBigInteger(publicKey.Exponent);
            BigInteger verified = BigInteger.ModPow(signature, e, n);
            return verified == m;
        }

        /// <summary>
        /// Converts a string into a BigInteger.
        /// </summary>
        public static BigInteger StringToBigInteger(string message)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(message);
            return new BigInteger(bytes);
        }
        /// <summary>
        /// Converts a big-endian byte array (from RSAParameters) into a positive BigInteger.
        /// </summary>
        public static BigInteger BytesToBigInteger(byte[] bytes)
        {
            // Reverse the byte array (RSAParameters are big-endian; BigInteger expects little-endian)
            // and append a 0 byte to force a positive value.
            return new BigInteger(bytes.Reverse().Concat(new byte[] { 0 }).ToArray());
        }

        /// <summary>
        /// Generates a random BigInteger r such that 2 <= r < max and gcd(r, max) == 1.
        /// Uses a cryptographically secure random number generator.
        /// </summary>
        private static BigInteger GenerateRandomBigInteger(BigInteger max)
        {
            int byteLength = max.ToByteArray().Length;
            byte[] bytes = new byte[byteLength];
            BigInteger r;
            do
            {
                RandomNumberGenerator.Fill(bytes);
                // Ensure the generated number is positive.
                bytes[bytes.Length - 1] &= 0x7F;
                r = new BigInteger(bytes);
            } while (r < 2 || r >= max || BigInteger.GreatestCommonDivisor(r, max) != 1);
            return r;
        }

        /// <summary>
        /// Computes the modular inverse of a modulo m using the Extended Euclidean Algorithm.
        /// </summary>
        private static BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            BigInteger m0 = m, t, q;
            BigInteger x0 = 0, x1 = 1;

            if (m == 1)
                return 0;

            while (a > 1)
            {
                q = a / m;
                t = m;
                m = a % m;
                a = t;
                t = x0;
                x0 = x1 - q * x0;
                x1 = t;
            }
            if (x1 < 0)
                x1 += m0;
            return x1;
        }
    }
}
