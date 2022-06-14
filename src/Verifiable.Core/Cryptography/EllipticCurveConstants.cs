using System;
using System.Numerics;

namespace Verifiable.Core.Cryptography
{
    /// <summary>
    /// Constants to work with Elliptic curve function.
    /// </summary>
    public static class EllipticCurveConstants
    {
        //NOTE: The lenghts of the constant byte arrays are well known. They are explicitly marked in the definitions to catch typing errors.

        /// <summary>
        /// These are precomputed constants for P-256 elliptic curve. The source of definitions is at
        /// <see href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186-draft.pdf">Draft NIST Special Publication 800-186
        /// Recommendations for Discrete Logarithm-Based Cryptography: Elliptic Curve Domain Parameters</see> page 13.
        /// </summary>
        public static class P256
        {
            /// <summary>
            /// The length of a P-256 byte array.
            /// </summary>
            public static int PointArrayLength => 32;

            // <summary>
            /// This is calculated using formula PrimeBytes = BigInteger.Pow(2, 256) - BigInteger.Pow(2, 224) + BigInteger.Pow(2, 192) + BigInteger.Pow(2, 96) - 1;
            /// </summary>
            /// <remarks>
            /// <list type="table">
            ///     <item>
            ///         <term>Decimal</term>
            ///         <description>115792089210356248762697446949407573530086143415290314195533631308867097853951</description>.
            ///     </item>
            ///     <item>            
            ///         <term>Hexadecimal</term>
            ///         <description>0xffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff</description>.
            ///     </item>
            /// </list>
            /// </remarks>
            public static ReadOnlySpan<byte> PrimeBytes => new byte[32] { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

            /// <summary>
            /// This is a constant from the NIST document.
            /// </summary>
            /// <remarks>
            /// <list type="table">
            ///     <item>
            ///         <term>Decimal</term>
            ///         <description>41058363725152142129326129780047268409114441015993725554835256314039467401291</description>.
            ///     </item>
            ///     <item>
            ///         <term>Hexadecimal</term>
            ///         <description> 0x5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6 3bce3c3e 27d2604b</description>.
            ///     </item>
            /// </list>
            /// </remarks>
            public static ReadOnlySpan<byte> CoefficientBBytes => new byte[32] { 0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b };

            /// <summary>
            /// This is calculated using formula PIdentityBytes = (Prime + 1) / 4;
            /// <remarks>
            /// <list type="table">
            ///     <item>
            ///         <term>Decimal</term>
            ///         <description>115792089210356248762697446949407573530086143415290314195533631308867097853951</description>.
            ///     </item>
            ///     <item>
            ///         <term>Hexadecimal</term>
            ///         <description>0xffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff</description>.
            ///     </item>
            /// </list>
            /// </remarks>
            /// </summary>
            public static ReadOnlySpan<byte> PIdentityBytes => new byte[32] { 0x3f, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            /// <summary>
            /// Turns <see cref="PrimeBytes"/> into a <see cref="BigInteger"/> for calculations.
            /// </summary>
            public static BigInteger Prime => new(PrimeBytes, true, true);

            /// <summary>
            /// Turns <see cref="CoefficientBBytes"/> into a <see cref="BigInteger"/> for calculations.
            /// </summary>
            public static BigInteger CoefficientB => new(CoefficientBBytes, true, true);

            /// <summary>
            /// Turns <see cref="PIdentityBytes"/> into a <see cref="BigInteger"/> for calculations.
            /// </summary>
            public static BigInteger PIdentity => new(PIdentityBytes, true, true);
        }

        /// <summary>
        /// These are precomputed constants for P-256 elliptic curve. The source of definitions is at
        /// <see href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186-draft.pdf">Draft NIST Special Publication 800-186
        /// Recommendations for Discrete Logarithm-Based Cryptography: Elliptic Curve Domain Parameters</see> page 14.
        /// </summary>
        public static class P384
        {
            /// <summary>
            /// The length of a P-384 byte array.
            /// </summary>
            public static int PointArrayLength => 48;

            /// <summary>
            /// This is calculated using formula PrimeBytes = BigInteger.Pow(2, 384) - BigInteger.Pow(2, 128) - BigInteger.Pow(2, 96) + BigInteger.Pow(2, 32) - 1;
            /// </summary>
            /// <remarks>
            /// <list type="table">
            ///     <item>
            ///         <term>Decimal</term>
            ///         <description>39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319</description>.
            ///     </item>
            ///     <item>
            ///         <term>Hexadecimal</term>
            ///         <description>0xffffffff ffffffff ffffffff ffffffff ffffffff ffffffff 606 ffffffff fffffffe ffffffff 00000000 00000000 ffffffff</description>.
            ///     </item>
            /// </list>
            /// </remarks>
            public static ReadOnlySpan<byte> PrimeBytes => new byte[48] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff };

            /// <summary>
            /// This is a constant from the NIST document.
            /// </summary>
            /// <remarks>
            /// <list type="table">
            ///     <item>
            ///         <term>Decimal</term>
            ///         <description>27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575</description>.
            ///     </item>
            ///     <item>
            ///         <term>Hexadecimal</term>
            ///         <description>0xb3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112 623 0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef</description>.
            ///     </item>
            /// </list>
            /// </remarks>
            public static ReadOnlySpan<byte> CoefficientBBytes => new byte[48] { 0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4, 0x98, 0x8e, 0x05, 0x6b, 0xe3, 0xf8, 0x2d, 0x19, 0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12, 0x03, 0x14, 0x08, 0x8f, 0x50, 0x13, 0x87, 0x5a, 0xc6, 0x56, 0x39, 0x8d, 0x8a, 0x2e, 0xd1, 0x9d, 0x2a, 0x85, 0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef };

            /// <summary>
            /// This is calculated using formula PIdentityBytes = (Prime + 1) / 4;
            /// <remarks>
            /// <list type="table">
            ///     <item>
            ///         <term>Decimal</term>
            ///         <description>9850501549098619803069760025035903451269934817616361666987073351061430442874217582261816522064734500465401743278080</description>.
            ///     </item>
            ///     <item>
            ///         <term>Hexadecimal</term>
            ///         <description>0x3fffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffff ffffffff ffffbfff ffffc000 00000000 00004000 0000</description>.
            ///     </item>
            /// </list>
            /// </remarks>
            /// </summary>
            public static ReadOnlySpan<byte> PIdentityBytes => new byte[48] { 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbf, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 };

            /// <summary>
            /// Turns <see cref="PrimeBytes"/> into a <see cref="BigInteger"/> for calculations.
            /// </summary>
            public static BigInteger Prime => new(PrimeBytes, true, true);

            /// <summary>
            /// Turns <see cref="CoefficientBBytes"/> into a <see cref="BigInteger"/> for calculations.
            /// </summary>
            public static BigInteger CoefficientB => new(CoefficientBBytes, true, true);

            /// <summary>
            /// Turns <see cref="PIdentityBytes"/> into a <see cref="BigInteger"/> for calculations.
            /// </summary>
            public static BigInteger PIdentity => new(PIdentityBytes, true, true);
        }

        /// <summary>
        /// These are precomputed constants for P-256 elliptic curve. The source of definitions is at
        /// <see href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186-draft.pdf">Draft NIST Special Publication 800-186
        /// Recommendations for Discrete Logarithm-Based Cryptography: Elliptic Curve Domain Parameters</see> page 15.
        /// </summary>
        public static class P521
        {
            /// <summary>
            /// The length of a P-521 byte array.
            /// </summary>
            public static int PointArrayLength => 66;

            /// <summary>
            /// This is calculated using formula PrimeBytes = BigInteger.Pow(2, 521) - 1;
            /// </summary>
            /// <remarks>
            /// <list type="table">
            ///     <item>
            ///         <term>Decimal</term>
            ///         <description>6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151</description>.
            ///     </item>
            ///     <item>            
            ///         <term>Hexadecimal</term>
            ///         <description>0x1ff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff</description>.
            ///     </item>
            /// </list>
            /// </remarks>
            public static ReadOnlySpan<byte> PrimeBytes => new byte[66] { 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

            /// <summary>
            /// This is a constant from the NIST document.
            /// </summary>
            /// <remarks>
            /// <list type="table">
            ///     <item>
            ///         <term>Decimal</term>
            ///         <description>1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984</description>.
            ///     </item>
            ///     <item>
            ///         <term>Hexadecimal</term>
            ///         <description>0x051 953eb961 8e1c9a1f 929a21a0 b68540ee a2da725b 99b315f3 b8b48991 8ef109e1 56193951 ec7e937b 1652c0bd 3bb1bf07 3573df88 3d2c34f1 ef451fd4 6b503f00</description>.
            ///     </item>
            /// </list>
            /// </remarks>
            public static ReadOnlySpan<byte> CoefficientBBytes => new byte[65] { 0x51, 0x95, 0x3e, 0xb9, 0x61, 0x8e, 0x1c, 0x9a, 0x1f, 0x92, 0x9a, 0x21, 0xa0, 0xb6, 0x85, 0x40, 0xee, 0xa2, 0xda, 0x72, 0x5b, 0x99, 0xb3, 0x15, 0xf3, 0xb8, 0xb4, 0x89, 0x91, 0x8e, 0xf1, 0x09, 0xe1, 0x56, 0x19, 0x39, 0x51, 0xec, 0x7e, 0x93, 0x7b, 0x16, 0x52, 0xc0, 0xbd, 0x3b, 0xb1, 0xbf, 0x07, 0x35, 0x73, 0xdf, 0x88, 0x3d, 0x2c, 0x34, 0xf1, 0xef, 0x45, 0x1f, 0xd4, 0x6b, 0x50, 0x3f, 0x00, };

            /// <summary>
            /// This is calculated using formula PIdentityBytes = (Prime + 1) / 4;
            /// <remarks>
            /// <list type="table">
            ///     <item>
            ///         <term>Decimal</term>
            ///         <description>1716199415032652428745475199770348304317358825035826352348615864796385795849414013030639910165363638744324077847870214509280496999929160953143507072778764288</description>.
            ///     </item>
            ///     <item>            
            ///         <term>Hexadecimal</term>            
            ///         <description>0x80000000 00000000 00000000 00000000 00000000 00000000 0000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 000000</description>.
            ///     </item>
            /// </list>
            /// </remarks>
            /// </summary>
            public static ReadOnlySpan<byte> PIdentityBytes => new byte[65] { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            /// <summary>
            /// Turns <see cref="PrimeBytes"/> into a <see cref="BigInteger"/> for calculations.
            /// </summary>
            public static BigInteger Prime => new(PrimeBytes, true, true);

            /// <summary>
            /// Turns <see cref="CoefficientBBytes"/> into a <see cref="BigInteger"/> for calculations.
            /// </summary>
            public static BigInteger CoefficientB => new(CoefficientBBytes, true, true);

            /// <summary>
            /// Turns <see cref="PIdentityBytes"/> into a <see cref="BigInteger"/> for calculations.
            /// </summary>
            public static BigInteger PIdentity => new(PIdentityBytes, true, true);
        }
    }
}
