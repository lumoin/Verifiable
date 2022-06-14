using SimpleBase;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using Verifiable.Core;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Did;
using Verifiable.NSec;
using Xunit;

namespace Verifiable.Tests
{
    public class MultibaseEncodingTests
    {
        private static MultiBaseEncoder Btc58MultibaseConverter => new(MultibaseAlgorithms.Base58Btc, Base58.Bitcoin.Encode);

        /// <summary>
        /// The DID supported curves. These are used to generate keys for testing.
        /// </summary>
        public static IEnumerable<object[]> NistEllipticCurves => new object[][]
        {
            new object[] { ECCurve.NamedCurves.nistP256, MulticodecHeaders.P256PublicKey.ToArray(), "zDn" },
            new object[] { ECCurve.NamedCurves.nistP384, MulticodecHeaders.P384PublicKey.ToArray(), "z82" },
            new object[] { ECCurve.NamedCurves.nistP521, MulticodecHeaders.P521PublicKey.ToArray(), "z2J9" }
        };


        /// <summary>
        /// The DID supported curves. These are used to generate keys for testing.
        /// </summary>
        public static IEnumerable<object[]> Rsa => new object[][]
        {
            new object[] { 2048, MulticodecHeaders.RsaPublicKey.ToArray(), "z4MX" },
            new object[] { 4096, MulticodecHeaders.RsaPublicKey.ToArray(), "zgg" }
        };


        [Theory]
        [MemberData(nameof(NistEllipticCurves))]
        public void NistEllipticCurvesWithMultibaseBtc58Succeeds(ECCurve curve, byte[] multicodecHeader, string prefix)
        {
            using(var key = ECDsa.Create(curve))
            {
                var parameters = key.ExportParameters(includePrivateParameters: false);
                var compressed = EllipticCurveUtilities.Compress(parameters.Q.X, parameters.Q.Y);

                var multibaseEncodedKey = KeyEncoding.MulticodecEncode(compressed, multicodecHeader, Btc58MultibaseConverter);
                Assert.StartsWith(prefix, multibaseEncodedKey, StringComparison.InvariantCulture);
            }
        }

        
        [Theory]
        [MemberData(nameof(Rsa))]
        public void RsaWithMultibaseBtc58Succeeds(int keyLength, byte[] multicodecHeader, string prefix)
        {
            using(var key = RSA.Create(keyLength))
            {
                var parameters = key.ExportParameters(includePrivateParameters: false);
                var modulus = parameters.Modulus!;
                var encodedModulus = RsaUtilities.Encode(modulus);

                var multibaseEncodedkey = KeyEncoding.MulticodecEncode(encodedModulus, multicodecHeader, Btc58MultibaseConverter);
                Assert.StartsWith(prefix, multibaseEncodedkey, StringComparison.InvariantCulture);
            }
        }


        [Fact]
        public void Ed25519WithMultibaseBtc58Succeeds()
        {
            var keyGenerator = new NSecKeyGenerator();
            var keys = keyGenerator.GenerateEd25519PublicPrivateKeyPair(MemoryPool<byte>.Shared);
            var publicKeyEd25519 = keys.PublicKeyMemory.AsReadOnlySpan();
            var privateKeyEd25519 = keys.PrivateKeyMemory.AsReadOnlySpan();

            var multibaseEncodedPublicKey = KeyEncoding.MulticodecEncode(publicKeyEd25519, MulticodecHeaders.Ed25519PublicKey, Btc58MultibaseConverter);
            var multibaseEncodedPrivateKey = KeyEncoding.MulticodecEncode(privateKeyEd25519, MulticodecHeaders.Ed25519PrivateKey, Btc58MultibaseConverter);

            Assert.StartsWith("z6Mk", multibaseEncodedPublicKey);
            Assert.StartsWith("z3u2", multibaseEncodedPrivateKey);
        }

        /*
        [Fact]
        public void X25519WithMultibaseBtc58Succeeds()
        {
            var keyGenerator = new NSecKeyGenerator();
            var keys = keyGenerator.GenerateEd25519PublicPrivateKeyPair(MemoryPool<byte>.Shared);
            var publicKeyEd25519 = keys.PublicKeyMemory.AsReadOnlySpan();
            var privateKeyEd25519 = keys.PrivateKeyMemory.AsReadOnlySpan();

            var x25519PublicKey = Sodium.ConvertEd25519PublicKeyToCurve25519PublicKey(publicKeyEd25519.ToArray());
            var x25519PrivateKey = Sodium.ConvertEd25519PrivateKeyToCurve25519PrivateKey(privateKeyEd25519.ToArray());
                        
            var multibaseEncodedPublicKey = KeyEncoding.MulticodecEncode(x25519PublicKey, MulticodecHeaders.X25519PublicKey, Btc58MultibaseConverter);
            var multibaseEncodedPrivateKey = KeyEncoding.MulticodecEncode(x25519PrivateKey, MulticodecHeaders.X25519PrivateKey, Btc58MultibaseConverter);

            Assert.StartsWith("z6LS", multibaseEncodedPublicKey);
            Assert.StartsWith("z3we", multibaseEncodedPrivateKey);
        }*/
    }
}
