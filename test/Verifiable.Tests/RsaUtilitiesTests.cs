using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Verifiable.Core.Cryptography;
using Xunit;

namespace Verifiable.Tests
{
    /// <summary>
    /// Tests for RSA utilities.
    /// </summary>
    public class RsaUtilitiesTests
    {
        /// <summary>
        /// Test array that is wrong length for RSA encoding.
        /// </summary>
        private static byte[] WrongSizeArray1 => Array.Empty<byte>();

        /// <summary>
        /// Test array that is wrong length for RSA encoding.
        /// </summary>
        private static byte[] WrongSizeArray2 => new byte[257];

        /// <summary>
        /// The RSA key lenghts DID specifications support.
        /// </summary>
        public static IEnumerable<object[]> RsaKeyLengths => new object[][]
        {
            new object[] { 2048 },
            new object[] { 4096 }            
        };


        [Fact]
        public void EncodeThrowsWithCorrectMessageIfModulusNull()
        {
            const string ParameterName = "rsaModulusBytes";
            var exception1 = Assert.Throws<ArgumentNullException>(() => RsaUtilities.Encode(null));
            Assert.Equal(ParameterName, exception1.ParamName);
        }


        [Fact]
        public void EncodeThrowsWithCorrectMessageIfModulusNotCorrectLength()
        {
            const string ParameterName = "rsaModulusBytes";
            var exception1 = Assert.Throws<ArgumentOutOfRangeException>(() => RsaUtilities.Encode(WrongSizeArray1));
            Assert.Equal(ParameterName, exception1.ParamName);
            Assert.Equal($"Length must be {RsaUtilities.Rsa2048ModulusLength} or {RsaUtilities.Rsa4096ModulusLength}. (Parameter '{ParameterName}')", exception1.Message);

            var exception2 = Assert.Throws<ArgumentOutOfRangeException>(() => RsaUtilities.Encode(WrongSizeArray2));
            Assert.Equal(ParameterName, exception2.ParamName);
            Assert.Equal($"Length must be {RsaUtilities.Rsa2048ModulusLength} or {RsaUtilities.Rsa4096ModulusLength}. (Parameter '{ParameterName}')", exception2.Message);
        }


        [Fact]
        public void DecodeThrowsWithCorrectMessageIfModulusNotCorrectLength()
        {
            const string ParameterName = "encodedRsaModulusBytes";
            const int Rsa2048DerEncodedBytesLength = 270;
            const int Rsa4096DerEncodedBytesLength = 526;
            var exception1 = Assert.Throws<ArgumentOutOfRangeException>(() => RsaUtilities.Decode(WrongSizeArray1));
            Assert.Equal(ParameterName, exception1.ParamName);
            Assert.Equal($"Length must be {Rsa2048DerEncodedBytesLength} or {Rsa4096DerEncodedBytesLength}. (Parameter '{ParameterName}')", exception1.Message);

            var exception2 = Assert.Throws<ArgumentOutOfRangeException>(() => RsaUtilities.Decode(WrongSizeArray2));
            Assert.Equal(ParameterName, exception2.ParamName);
            Assert.Equal($"Length must be {Rsa2048DerEncodedBytesLength} or {Rsa4096DerEncodedBytesLength}. (Parameter '{ParameterName}')", exception2.Message);
        }


        [Theory]
        [MemberData(nameof(RsaKeyLengths))]
        public void RsaDecodeThrowsIfNoDerPaddingByte(int rsaKeyLength)
        {
            const string CatastrophicExceptionMessage = "Catastrophic error while decoding RSA modulus bytes.";
            const int PaddingByteIndex = 8;

            using(var rsaKey = RSA.Create(rsaKeyLength))
            {
                var rsaParameters = rsaKey.ExportParameters(includePrivateParameters: false);
                var rsaModulus = rsaParameters.Modulus!;

                var encodedModulus = RsaUtilities.Encode(rsaModulus);
                encodedModulus[PaddingByteIndex] = 0x1;

                var exception = Assert.Throws<ArgumentException>(() => RsaUtilities.Decode(RsaUtilities.Decode(encodedModulus)));
                Assert.Equal(CatastrophicExceptionMessage, exception.Message);
            }
        }


        [Theory]
        [MemberData(nameof(RsaKeyLengths))]
        public void RsaDecodeThrowsIfNoMsbSet(int rsaKeyLength)
        {
            const string CatastrophicExceptionMessage = "Catastrophic error while decoding RSA modulus bytes.";
            const int MsbByteIndex = 9;

            using(var rsaKey = RSA.Create(rsaKeyLength))
            {
                var rsaParameters = rsaKey.ExportParameters(includePrivateParameters: false);
                var rsaModulus = rsaParameters.Modulus!;

                var encodedModulus = RsaUtilities.Encode(rsaModulus);
                encodedModulus[MsbByteIndex] = 0x1;

                var exception = Assert.Throws<ArgumentException>(() => RsaUtilities.Decode(RsaUtilities.Decode(encodedModulus)));
                Assert.Equal(CatastrophicExceptionMessage, exception.Message);
            }
        }

        
        [Theory]
        [MemberData(nameof(RsaKeyLengths))]
        public void Rsa2048EncodingAndDecodingSucceeds(int rsaKeyLength)
        {
            using(var rsaKey = RSA.Create(rsaKeyLength))
            {
                var rsaParameters = rsaKey.ExportParameters(includePrivateParameters: false);
                var rsaModulus = rsaParameters.Modulus!;

                var encodedModulus = RsaUtilities.Encode(rsaModulus);
                var decodedModulus = RsaUtilities.Decode(encodedModulus);

                Assert.Equal(rsaModulus, decodedModulus);
            }
        }
    }
}
