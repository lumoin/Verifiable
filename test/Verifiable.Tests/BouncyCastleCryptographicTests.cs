using Verifiable.BouncyCastle;
using Verifiable.Core.Cryptography;
using System;
using System.Buffers;
using System.Text;
using Xunit;

namespace Verifiable.Core
{
    /// <summary>
    /// These test specifically BouncyCastle as the cryptographic provider.
    /// </summary>
    public class BouncyCastleCryptographicTests
    {
        /// <summary>
        /// Used in tests as test data.
        /// </summary>
        private byte[] TestData { get; } = Encoding.UTF8.GetBytes("This is a test string.");

        /// <summary>
        /// A key generator.
        /// </summary>
        private IKeyGenerator KeyGenerator { get; } = new BouncyCastleKeyGenerator();


        [Fact]
        public void CanGenerateKeyPairEd255019()
        {
            var keys = KeyGenerator.GenerateEd25519PublicPrivateKeyPair(MemoryPool<byte>.Shared);
            Assert.NotNull(keys.Item1);
            Assert.NotNull(keys.Item2);
        }


        [Fact]
        public void CanSignAndVerifyEd255019()
        {
            var keys = KeyGenerator.GenerateEd25519PublicPrivateKeyPair(MemoryPool<byte>.Shared);
            var publicKey = keys.Item1;
            var privateKey = keys.Item2;

            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, BouncyCastleAlgorithms.SignEd25519, MemoryPool<byte>.Shared);
            Assert.True(publicKey.Verify(data, signature, BouncyCastleAlgorithms.VerifyEd25519));
        }


        [Fact]
        public void CanCreateIdentifiedKeyAndVerify()
        {
            var keys = KeyGenerator.GenerateEd25519PublicPrivateKeyPair(MemoryPool<byte>.Shared);

            var publicKey = new Core.Cryptography.PublicKey(keys.Item1, "Test-1", BouncyCastleAlgorithms.VerifyEd25519);
            var privateKey = new PrivateKey(keys.Item2, "Test-1", BouncyCastleAlgorithms.SignEd25519);

            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, MemoryPool<byte>.Shared);
            Assert.True(publicKey.Verify(data, signature));
        }
    }
}
