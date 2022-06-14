using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Verifiable.Core.Cryptography;
using Xunit;

namespace Verifiable.Tests
{
    /// <summary>
    /// Tests for RSA utilities.
    /// </summary>
    public class EllipticCurveUtilitiesTests
    {
        /// <summary>
        /// The DID supported curves. These are used to generate keys for testing.
        /// </summary>
        public static IEnumerable<object[]> Curves => new object[][]
        {
            new object[] { ECCurve.NamedCurves.nistP256 },
            new object[] { ECCurve.NamedCurves.nistP384 },
            new object[] { ECCurve.NamedCurves.nistP521 }            
        };

        
        [Theory]
        [MemberData(nameof(Curves))]
        public void NistCurvesCompressAndDecompressSucceeds(ECCurve curve)
        {
            ECDsa? evenKey = null;
            ECDsa? oddKey = null;
            while(evenKey == null || oddKey == null)
            {
                var loopKey = ECDsa.Create(curve);
                var loopParams = loopKey.ExportParameters(includePrivateParameters: false);
                var loopSignByte = EllipticCurveUtilities.CompressionSignByte(loopParams.Q.Y);
                if(loopSignByte == 0x02)
                {
                    evenKey = loopKey;
                }
                else
                {
                    oddKey = loopKey;
                }
            }

            ECParameters evenKeyParameters = evenKey.ExportParameters(includePrivateParameters: true);
            var evenCompressedPoint = EllipticCurveUtilities.Compress(evenKeyParameters.Q.X, evenKeyParameters.Q.Y);
            var evenUncompressedY = EllipticCurveUtilities.Decompress(evenCompressedPoint);
            Assert.Equal(evenKeyParameters.Q.Y, evenUncompressedY);

            ECParameters oddKeyParameters = evenKey.ExportParameters(includePrivateParameters: true);
            var oddCompressedPoint = EllipticCurveUtilities.Compress(oddKeyParameters.Q.X, oddKeyParameters.Q.Y);
            var oddUncompressedY = EllipticCurveUtilities.Decompress(oddCompressedPoint);
            Assert.Equal(oddKeyParameters.Q.Y, oddUncompressedY);
        }


        [Fact]
        public void CompressThrowsWithCorrectMessageIfEitherOrBothParametersNull()
        {
            using(var key = ECDsa.Create())
            {
                var keyParams = key.ExportParameters(includePrivateParameters: false);

                const string XParameterName = "xPoint";
                var exception1 = Assert.Throws<ArgumentNullException>(() => EllipticCurveUtilities.Compress(null, keyParams.Q.Y));
                Assert.Equal(XParameterName, exception1.ParamName);

                const string YParameterName = "yPoint";
                var exception2 = Assert.Throws<ArgumentNullException>(() => EllipticCurveUtilities.Compress(keyParams.Q.X, null));
                Assert.Equal(YParameterName, exception2.ParamName);

                var exception3 = Assert.Throws<ArgumentNullException>(() => EllipticCurveUtilities.Compress(null, null));
                Assert.Equal(XParameterName, exception3.ParamName);
            }
        }


        [Fact]
        public void CompressThrowsWithCorrectMessageIfPointsDifferentLength()
        {
            using(var key1 = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                using(var key2 = ECDsa.Create(ECCurve.NamedCurves.nistP384))
                {
                    var keyParams1 = key1.ExportParameters(includePrivateParameters: false);
                    var keyParams2 = key2.ExportParameters(includePrivateParameters: false);

                    const string ExceptionMessage = "Parameters 'xPoint' and 'yPoint' need to be of the same length.";
                    var exception = Assert.Throws<ArgumentException>(() => EllipticCurveUtilities.Compress(keyParams1.Q.X!, keyParams2.Q.Y));
                    Assert.Equal(ExceptionMessage, exception.Message);
                }
            }
        }


        [Fact]
        public void CompressThrowsWithCorrectMessageIfPointsWrongLength()
        {
            using(var key1 = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var keyParams1 = key1.ExportParameters(includePrivateParameters: false);

                const string XParameterName = "xPoint";
                string xPointExceptionMessage = $"Length must be '{EllipticCurveConstants.P256.PointArrayLength}', '{EllipticCurveConstants.P384.PointArrayLength}' or '{EllipticCurveConstants.P521.PointArrayLength}'. (Parameter 'xPoint')";
                var xException = Assert.Throws<ArgumentOutOfRangeException>(() => EllipticCurveUtilities.Compress(keyParams1.Q.X!.Concat(new byte[] { 0x00 }).ToArray(), keyParams1.Q.Y));
                Assert.Equal(XParameterName, xException.ParamName);
                Assert.Equal(xPointExceptionMessage, xException.Message);

                const string YParameterName = "yPoint";
                string yPointExceptionMessage = $"Length must be '{EllipticCurveConstants.P256.PointArrayLength}', '{EllipticCurveConstants.P384.PointArrayLength}' or '{EllipticCurveConstants.P521.PointArrayLength}'. (Parameter 'yPoint')";
                var yException = Assert.Throws<ArgumentOutOfRangeException>(() => EllipticCurveUtilities.Compress(keyParams1.Q.X!, keyParams1.Q.Y!.Concat(new byte[] { 0x00 }).ToArray()));
                Assert.Equal(YParameterName, yException.ParamName);
                Assert.Equal(yPointExceptionMessage, yException.Message);
            }
        }
    }
}
