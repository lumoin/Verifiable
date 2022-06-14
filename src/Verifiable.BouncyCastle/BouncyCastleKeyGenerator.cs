using Verifiable.Core.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Buffers;
using Org.BouncyCastle.Crypto.Agreement;

namespace Verifiable.BouncyCastle
{
    //TODO: Look at BouncyCastleAlgorithms and KeyExtensions as for examples how to create these memories to be used elsewhere.

    /// <inheritdoc />
    public class BouncyCastleKeyGenerator: IKeyGenerator
    {
        /// <inheritdoc />
        public (PublicKeyMemory PublicKeyMemory, PrivateKeyMemory PrivateKeyMemory) GenerateEd25519PublicPrivateKeyPair(MemoryPool<byte> keyMemoryPool)
        {
            /*var seed = new byte[] { 0x1 };
            var randomnessGenerator = SecureRandom.GetInstance("SHA256PRNG", autoSeed: false);
            randomnessGenerator.SetSeed(seed);*/
            var randomnessGenerator = SecureRandom.GetInstance("SHA256PRNG", autoSeed: true);

            var keyPairGenerator = new Ed25519KeyPairGenerator();
            keyPairGenerator.Init(new Ed25519KeyGenerationParameters(randomnessGenerator));
            var keyPair = keyPairGenerator.GenerateKeyPair();

            ReadOnlySpan<byte> publicKeyBytes = ((Ed25519PublicKeyParameters)keyPair.Public).GetEncoded();
            ReadOnlySpan<byte> privateKeyBytes = ((Ed25519PrivateKeyParameters)keyPair.Private).GetEncoded();

            var publicKeyBuffer = keyMemoryPool.Rent(publicKeyBytes.Length);
            var privateKeyBuffer = keyMemoryPool.Rent(privateKeyBytes.Length);

            publicKeyBytes.CopyTo(publicKeyBuffer.Memory.Span);
            privateKeyBytes.CopyTo(privateKeyBuffer.Memory.Span);

            var publicKey = new PublicKeyMemory(publicKeyBuffer);
            var privateKey = new PrivateKeyMemory(privateKeyBuffer);

            return (publicKey, privateKey);
        }


        public (PublicKeyMemory PublicKeyMemory, PrivateKeyMemory PrivateKeyMemory) GenerateX25519PublicPrivateKeyPair2(string seed, MemoryPool<byte> keyMemoryPool)
        {
            var randomnessGenerator = SecureRandom.GetInstance("SHA256PRNG", autoSeed: true);
            var keyPairGenerator = new X25519KeyPairGenerator();
            keyPairGenerator.Init(new X25519KeyGenerationParameters(randomnessGenerator));
            var keyPair = keyPairGenerator.GenerateKeyPair();

            ReadOnlySpan<byte> publicKeyBytes = ((X25519PublicKeyParameters)keyPair.Public).GetEncoded();
            ReadOnlySpan<byte> privateKeyBytes = ((X25519PrivateKeyParameters)keyPair.Private).GetEncoded();

            var publicKeyBuffer = keyMemoryPool.Rent(publicKeyBytes.Length);
            var privateKeyBuffer = keyMemoryPool.Rent(privateKeyBytes.Length);

            publicKeyBytes.CopyTo(publicKeyBuffer.Memory.Span);
            privateKeyBytes.CopyTo(privateKeyBuffer.Memory.Span);

            var publicKey = new PublicKeyMemory(publicKeyBuffer);
            var privateKey = new PrivateKeyMemory(privateKeyBuffer);

            return (publicKey, privateKey);
        }

        //TODO: Separate these, remove this interface.

        
        public (PublicKeyMemory PublicKeyMemory, PrivateKeyMemory PrivateKeyMemory) GenerateX25519PublicPrivateKeyPair(MemoryPool<byte> keyMemoryPool)
        {
            var randomnessGenerator = SecureRandom.GetInstance("SHA256PRNG", autoSeed: true);
            var keyPairGenerator = new X25519KeyPairGenerator();
            keyPairGenerator.Init(new X25519KeyGenerationParameters(randomnessGenerator));
            var keyPair = keyPairGenerator.GenerateKeyPair();

            ReadOnlySpan<byte> publicKeyBytes = ((X25519PublicKeyParameters)keyPair.Public).GetEncoded();
            ReadOnlySpan<byte> privateKeyBytes = ((X25519PrivateKeyParameters)keyPair.Private).GetEncoded();

            var publicKeyBuffer = keyMemoryPool.Rent(publicKeyBytes.Length);
            var privateKeyBuffer = keyMemoryPool.Rent(privateKeyBytes.Length);

            publicKeyBytes.CopyTo(publicKeyBuffer.Memory.Span);
            privateKeyBytes.CopyTo(privateKeyBuffer.Memory.Span);

            var publicKey = new PublicKeyMemory(publicKeyBuffer);
            var privateKey = new PrivateKeyMemory(privateKeyBuffer);

            return (publicKey, privateKey);
        }
    }
}
