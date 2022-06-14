using Verifiable.Core.Cryptography;
using Verifiable.NSec;
using System;
using System.Buffers;
using System.Text;
using Xunit;


namespace Verifiable.Tests
{
    /// <summary>
    /// These test specifically NSec as the cryptographic provider.
    /// </summary>
    public class NSecCryptographicTests
    {
        /// <summary>
        /// Used in tests as test data.
        /// </summary>
        private byte[] TestData { get; } = Encoding.UTF8.GetBytes("This is a test string.");

        /// <summary>
        /// A key generator.
        /// </summary>
        private IKeyGenerator KeyGenerator { get; } = new NSecKeyGenerator();


        [Fact]
        public void CanGenerateKeyPairEd255019()
        {
            var keys = KeyGenerator.GenerateEd25519PublicPrivateKeyPair(MemoryPool<byte>.Shared);
            Assert.NotNull(keys.PublicKeyMemory);
            Assert.NotNull(keys.PrivateKeyMemory);
        }


        [Fact]
        public void CanSignAndVerifyEd255019()
        {
            var keys = KeyGenerator.GenerateEd25519PublicPrivateKeyPair(MemoryPool<byte>.Shared);
            var publicKey = keys.PublicKeyMemory;
            var privateKey = keys.PrivateKeyMemory;

            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, NSecAlgorithms.SignEd25519, MemoryPool<byte>.Shared);
            Assert.True(publicKey.Verify(data, signature, NSecAlgorithms.VerifyEd25519));
        }


        [Fact]
        public void CanCreateIdentifiedKeyAndVerify()
        {
            var keys = KeyGenerator.GenerateEd25519PublicPrivateKeyPair(MemoryPool<byte>.Shared);

            var publicKey = new Core.Cryptography.PublicKey(keys.PublicKeyMemory, "Test-1", NSecAlgorithms.VerifyEd25519);
            var privateKey = new PrivateKey(keys.PrivateKeyMemory, "Test-1", NSecAlgorithms.SignEd25519);

            var data = (ReadOnlySpan<byte>)TestData;
            using var signature = privateKey.Sign(data, MemoryPool<byte>.Shared);
            Assert.True(publicKey.Verify(data, signature));
        }
    }
}