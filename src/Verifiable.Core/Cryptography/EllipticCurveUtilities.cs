using System;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace Verifiable.Core.Cryptography
{
    /// <summary>
    /// These are some helper bit functions to work with elliptic key material.
    /// </summary>
    public static class EllipticCurveUtilities
    {
        /// <summary>
        /// Even Y coordinate. See <see href="https://www.secg.org/sec1-v2.pdf">SEC 1: Elliptic Curve Cryptography</see> page 11.
        /// </summary>
        /// <remarks>Also see <see href="https://datatracker.ietf.org/doc/html/rfc5480">RFC 5480:
        /// Elliptic Curve Cryptography Subject Public Key Information</see>.</remarks>
        public static byte EvenYCoordinate => 0x02;

        /// <summary>
        /// Odd Y coordinate. See <see href="https://www.secg.org/sec1-v2.pdf">SEC 1: Elliptic Curve Cryptography</see> page 11.
        /// </summary>
        /// <remarks>Also see <see href="https://datatracker.ietf.org/doc/html/rfc5480">RFC 5480:
        /// Elliptic Curve Cryptography Subject Public Key Information</see>.</remarks>
        public static byte OddYCoordinate => 0x03;

        /// <summary>
        /// Uncompressed format for elliptic curve points that are concated. Not supported.
        /// </summary>
        /// <remarks>Also see <see href="https://datatracker.ietf.org/doc/html/rfc5480">RFC 5480:
        /// Elliptic Curve Cryptography Subject Public Key Information</see>.</remarks>
        public static byte UnpackedCoordinates => 0x04;


        /// <summary>
        /// Decompresses a given point on the elliptic curve that is compressed on X point.
        /// </summary>
        /// <param name="compressedPoint">The X point to which the y point is compressed.</param>
        /// <returns>The y point matching the <paramref name="compressedPoint"/> on the given elliptic curve.</returns>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="compressedPoint"/> must start with 0x02 or 0x03
        /// and be either 33 (P-256), 49 (P-384) or 67 (P-521) bytes</exception>.
        /// <remarks>This returns fixed length points for P-256 (33 bytes), P-384 (48 bytes) and P-521 (66 bytes).
        /// For P-521 this means padding with 0x00. This is not suitable for length-prepended structures such as
        /// certificate SubjectPublicKeyInfo fields.</remarks>
        public static byte[] Decompress(ReadOnlySpan<byte> compressedPoint)
        {
            const int P256CompressedByteCount = 33;
            const int P384CompressedByteCount = 49;
            const int P521CompressedByteCount = 67;

            if(compressedPoint[0] == UnpackedCoordinates)
            {
                throw new ArgumentOutOfRangeException(nameof(compressedPoint), "This method supports only compressed X coordinate (must start with 0x02 or 0x03).");
            }

            if(compressedPoint[0] != EvenYCoordinate && compressedPoint[0] != OddYCoordinate)
            {
                throw new ArgumentOutOfRangeException(nameof(compressedPoint), $"Value must start with 0x02 or 0x03. Now 0x{compressedPoint[0]:2}.");
            }

            if(!(compressedPoint.Length == P256CompressedByteCount
                || compressedPoint.Length == P384CompressedByteCount
                || compressedPoint.Length == P521CompressedByteCount))
            {
                throw new ArgumentOutOfRangeException(nameof(compressedPoint), $"Length must be {P256CompressedByteCount}, {P384CompressedByteCount} or {P521CompressedByteCount}.");
            }

            //These local methods are used to make the code easier to follow by naming
            //the key operations.
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            static BigInteger CalcuateYPoint(BigInteger x, BigInteger coefficientB, BigInteger pIdentity, BigInteger prime)
            {
                return BigInteger.ModPow(BigInteger.Pow(x, 3) - x * 3 + coefficientB, pIdentity, prime);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            static bool CalculateIsPositiveSign(ReadOnlySpan<byte> compressedXPoint, BigInteger calculatedYPoint)
            {
                int isPositiveY = compressedXPoint[0] - 2;
                return isPositiveY == calculatedYPoint % 2;
            }

            //This function writes to yPointBytes. The return value is used to smoothen code.
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            static byte[] WriteYPointBytes(BigInteger point, byte[] yPointBytes, int start)
            {
                //Writing these bytes should never fail. The output size is known and the buffer is already reserved.
                //Plus tests check the guards checking function data check other options are not possible.
                _ = point.TryWriteBytes(((Span<byte>)yPointBytes)[start..], out _, isUnsigned: true, isBigEndian: true);
                return yPointBytes;
            }

            //The first byte is to choose either y or -y. So, it's not the actual point payload data
            //and consequently needs to be sliced off.
            var x = new BigInteger(compressedPoint[1..], isUnsigned: true, isBigEndian: true);

            //The function guards checking parameters check one of the cases are the only valid ones.
            //Hence the last else branch needs to be 512 if it is not something else and the variables
            //will always be initialized.
            BigInteger coefficientB;
            BigInteger pIdent;
            BigInteger prime;
            int pointArrayLength;
            if(compressedPoint.Length == P256CompressedByteCount)
            {
                coefficientB = EllipticCurveConstants.P256.CoefficientB;
                pIdent = EllipticCurveConstants.P256.PIdentity;
                prime = EllipticCurveConstants.P256.Prime;
                pointArrayLength = EllipticCurveConstants.P256.PointArrayLength;
            }
            else if(compressedPoint.Length == P384CompressedByteCount)
            {
                coefficientB = EllipticCurveConstants.P384.CoefficientB;
                pIdent = EllipticCurveConstants.P384.PIdentity;
                prime = EllipticCurveConstants.P384.Prime;
                pointArrayLength = EllipticCurveConstants.P384.PointArrayLength;
            }
            else
            {
                coefficientB = EllipticCurveConstants.P521.CoefficientB;
                pIdent = EllipticCurveConstants.P521.PIdentity;
                prime = EllipticCurveConstants.P521.Prime;
                pointArrayLength = EllipticCurveConstants.P521.PointArrayLength;
            }

            var oneYPointCandinate = CalcuateYPoint(x, coefficientB, pIdent, prime);
            var anotherYPointCandinate = prime - oneYPointCandinate;
            bool isPositive = CalculateIsPositiveSign(compressedPoint, oneYPointCandinate);

            var returnYPointBytes = new byte[pointArrayLength];
            int returnYPointByteCount = isPositive ? oneYPointCandinate.GetByteCount(isUnsigned: true) : anotherYPointCandinate.GetByteCount(isUnsigned: true);
            int startIndexAfterPadding = pointArrayLength - returnYPointByteCount;

            //This is not 100 % constant time in all cases. In P-521 Y coordinate may have a leading zeroes which
            //BigInteger removes. In this case startIndexAfterPadding > 0 and consequently WriteYPointBytes assumes zero
            //initialized array, which it starts filling from that index onwards. There is no guarantee BigInteger
            //operations are constant time neither.
            return isPositive ?
                WriteYPointBytes(oneYPointCandinate, returnYPointBytes, startIndexAfterPadding) :
                WriteYPointBytes(anotherYPointCandinate, returnYPointBytes, startIndexAfterPadding);
        }


        /// <summary>
        /// Calculates the sign byte for the point that is added to the compressed
        /// point. This is used to choose either positive (0x02) or negative (0x03) point
        /// when the curve is again decompressed.
        /// See <see href="https://www.secg.org/sec1-v2.pdf">SEC 1: Elliptic Curve Cryptography</see> page 11.
        /// </summary>
        /// <param name="yPoint">The y parameter from which to deduce the sign.</param>
        /// <returns>The compression sign byte. Either 0x02 (positive) or 0x03 (negative)</returns>.
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="compressedPoint"/> nyst start with 0x02 or 0x03
        /// and be either 32 (P-256), 42 (P-384) or 66 (P-521) bytes</exception>.
        /// <remarks>Also see <see href="https://datatracker.ietf.org/doc/html/rfc5480">RFC 5480:
        /// Elliptic Curve Cryptography Subject Public Key Information</see>.</remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte CompressionSignByte(ReadOnlySpan<byte> yPoint)
        {
            if(!(yPoint.Length == EllipticCurveConstants.P256.PointArrayLength
                || yPoint.Length == EllipticCurveConstants.P384.PointArrayLength
                || yPoint.Length == EllipticCurveConstants.P521.PointArrayLength))
            {
                throw new ArgumentOutOfRangeException(nameof(yPoint), $"Length must be {EllipticCurveConstants.P256.PointArrayLength}, {EllipticCurveConstants.P384.PointArrayLength} or {EllipticCurveConstants.P521.PointArrayLength}.");
            }

            return (byte)(2 + (yPoint![^1] & 1));
        }


        /// <summary>
        /// Compresses elliptic curve points. See <see href="https://www.secg.org/sec1-v2.pdf">SEC 1: Elliptic Curve Cryptography</see> page 11.
        /// </summary>
        /// <param name="xPoint">The X point.</param>
        /// <param name="yPoint">The Y point.</param>
        /// <returns>The compressed elliptic point coordinates.</returns>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="compressedPoint"/> nyst start with 0x02 or 0x03
        /// and be either 32 (P-256), 42 (P-384) or 66 (P-521) bytes</exception>.
        /// <remarks>Also see <see href="https://datatracker.ietf.org/doc/html/rfc5480">RFC 5480:
        /// Elliptic Curve Cryptography Subject Public Key Information</see>.</remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] Compress(ReadOnlySpan<byte> xPoint, ReadOnlySpan<byte> yPoint)
        {
            if(xPoint == null)
            {
                throw new ArgumentNullException(nameof(xPoint));
            }

            if(yPoint == null)
            {
                throw new ArgumentNullException(nameof(yPoint));
            }

            if(!(xPoint.Length == EllipticCurveConstants.P256.PointArrayLength
                || xPoint.Length == EllipticCurveConstants.P384.PointArrayLength
                || xPoint.Length == EllipticCurveConstants.P521.PointArrayLength))
            {
                throw new ArgumentOutOfRangeException(nameof(xPoint),
                    $"Length must be '{EllipticCurveConstants.P256.PointArrayLength}', '{EllipticCurveConstants.P384.PointArrayLength}' or '{EllipticCurveConstants.P521.PointArrayLength}'.");
            }

            if(!(yPoint.Length == EllipticCurveConstants.P256.PointArrayLength
                || yPoint.Length == EllipticCurveConstants.P384.PointArrayLength
                || yPoint.Length == EllipticCurveConstants.P521.PointArrayLength))
            {
                throw new ArgumentOutOfRangeException(nameof(yPoint),
                    $"Length must be '{EllipticCurveConstants.P256.PointArrayLength}', '{EllipticCurveConstants.P384.PointArrayLength}' or '{EllipticCurveConstants.P521.PointArrayLength}'.");
            }

            if(xPoint.Length != yPoint.Length)
            {
                throw new ArgumentException($"Parameters '{nameof(xPoint)}' and '{nameof(yPoint)}' need to be of the same length.");
            }

            //Y point will be checked within Y point sign function.
            /*
            if(!(yPoint.Length == EllipticCurveConstants.P256.PointArrayLength
                || yPoint.Length == EllipticCurveConstants.P384.PointArrayLength
                || yPoint.Length == EllipticCurveConstants.P521.PointArrayLength))
            {
                throw new ArgumentOutOfRangeException(nameof(yPoint),
                    $"Length must be {EllipticCurveConstants.P256.PointArrayLength}, {EllipticCurveConstants.P384.PointArrayLength} or {EllipticCurveConstants.P521.PointArrayLength}.");
            }*/

            var compressedPointData = new byte[xPoint.Length + 1];
            compressedPointData[0] = CompressionSignByte(yPoint);
            xPoint.CopyTo(compressedPointData.AsSpan(1));

            return compressedPointData;
        }
    }
}
