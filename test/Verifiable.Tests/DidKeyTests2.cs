using Microsoft.IdentityModel.Tokens;
using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Did;
using Xunit;


namespace Verifiable.Tests
{
    public class KeyEncoding
    {
        public static string CreateBase64PublicDidKey(ReadOnlySpan<byte> keyBytes)
        {
            return Base64UrlEncoder.Encode(keyBytes.ToArray());
        }


        public static string MulticodecEncode(ReadOnlySpan<byte> data, ReadOnlySpan<byte> codecHeader, MultiBaseEncoder converter)
        {
            var encodedBufferLength = codecHeader.Length + data.Length;
            Span<byte> dataWithEncodingHeaders = stackalloc byte[encodedBufferLength];

            codecHeader.CopyTo(dataWithEncodingHeaders);
            data.CopyTo(dataWithEncodingHeaders.Slice(codecHeader.Length));

            return converter.Encode(dataWithEncodingHeaders);
            //return $"{converter.EncoderId}{converter.Encode(dataWithEncodingHeaders)}";

            //TODO: The data array returned from the pool ought be exact the data size or else the encoding produce a wrong result.
            //Also using a pool is better if one can choose the pool based on the data.
            /*
            var encodedBufferLength2 = codecHeader.Length + data.Length;
            byte[]? pool = null;
            Span<byte> dataWithEncodingHeaders2 = encodedBufferLength2 <= 512 ? stackalloc byte[encodedBufferLength2] : (pool = ArrayPool<byte>.Shared.Rent(encodedBufferLength2));

            codecHeader.CopyTo(dataWithEncodingHeaders2);
            data.CopyTo(dataWithEncodingHeaders2.Slice(codecHeader.Length));

            var multiencodedData = $"{converter.Encoder}{converter.Encode(dataWithEncodingHeaders2)}";
            if(pool != null)
            {
                ArrayPool<byte>.Shared.Return(pool);
            }

            return multiencodedData;*/
        }
    }

    /// <summary>
    /// Bundles together a multibase encoder and a identifier for it. For examples of
    /// identifiers see at <see cref="MultibaseAlgorithms"/>.
    /// </summary>
    /// <remarks>This is designed so that one can choose which concrete encoding implementation to use
    /// and also add new (private) implementations to the system.</remarks>
    public sealed class MultiBaseEncoder
    {
        /// <summary>
        /// The encoder function that matches <see cref="EncoderId"/>.
        /// </summary>
        private ReadOnlySpanFunc<byte, string> Encoder { get; }

        /// <summary>
        /// The encoder identifier. For examples see at <see cref="MultibaseAlgorithms"/>.
        /// </summary>
        public char EncoderId { get; }

        /// <summary>
        /// <see cref="MultiBaseEncoder"/> constructor.
        /// </summary>
        /// <param name="encoderId">The encoder identifier.</param>
        /// <param name="encoder"> The encoder function.</param>
        public MultiBaseEncoder(char encoderId, ReadOnlySpanFunc<byte, string> encoder)
        {
            ArgumentNullException.ThrowIfNull(encoderId);
            ArgumentNullException.ThrowIfNull(encoder);

            EncoderId = encoderId;
            Encoder = encoder;
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public string Encode(ReadOnlySpan<byte> data)
        {
            return Encode(data, EncoderId, Array.Empty<byte>(), Encoder);
        }

        //There could be a function that takes as input what a wrapper gives, then the wrapper putting it into KeyFormat type based on selectors.
        //So _actual key material encoding_ is a delegate such as ReadOnlySpanFunc<byte, string> encoder, maybe named. In which case
        //the wrapper comes with a selector, maybe that is the user, or application selectable part. The library just cares about making available
        //a builder that takes its input as builders that output DID types.

        private static string Encode(ReadOnlySpan<byte> data, char codecId, ReadOnlySpan<byte> codecHeader, ReadOnlySpanFunc<byte, string> encoder)
        {
            var encodedBufferLength = codecHeader.Length + data.Length;
            Span<byte> dataWithEncodingHeaders = stackalloc byte[encodedBufferLength];

            codecHeader.CopyTo(dataWithEncodingHeaders);
            data.CopyTo(dataWithEncodingHeaders.Slice(codecHeader.Length));

            return $"{codecId}{encoder(dataWithEncodingHeaders)}";
        }
    }


    /// <summary>
    /// Xyz.
    /// </summary>
    public static class JsonWebKeyThumbprintParameterNames
    {
        public static string Crv => "crv";

        public static string D => "d";

        public static string E => "e";

        public static string K => "k";

        public static string Kty => "kty";

        public static string N => "n";

        public static string X => "x";

        public static string Y => "y";


        /// <summary>
        /// Returns a value that indicates if the <paramref name="jsonAttribute"/> is <see cref="Crv"/>.
        /// </summary>
        /// <param name="jsonAttribute">The JSON attribute</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="Crv"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsCrv(string jsonAttribute)
        {
            return Equals(Crv, jsonAttribute);
        }


        /// <summary>
        /// Returns a value that indicates if the  <paramref name="jsonAttribute"/> is <see cref="D"/>.
        /// </summary>
        /// <param name="jsonAttribute">The JSON attribute</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="D"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsD(string jsonAttribute)
        {
            return Equals(D, jsonAttribute);
        }


        /// <summary>
        /// Returns a value that indicates if the <paramref name="jsonAttribute"/> is <see cref="E"/>.
        /// </summary>
        /// <param name="jsonAttribute">The JSON attribute</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="E"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsE(string jsonAttribute)
        {
            return Equals(E, jsonAttribute);
        }

        /// <summary>
        /// Returns a value that indicates if the <paramref name="jsonAttribute"/> is <see cref="K"/>.
        /// </summary>
        /// <param name="jsonAttribute">The JSON attribute</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="K"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsK(string jsonAttribute)
        {
            return Equals(K, jsonAttribute);
        }


        /// <summary>
        /// Returns a value that indicates if the <paramref name="jsonAttribute"/> is <see cref="Kty"/>.
        /// </summary>
        /// <param name="jsonAttribute">The JSON attribute</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="Kty"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsKty(string jsonAttribute)
        {
            return Equals(Kty, jsonAttribute);
        }


        /// <summary>
        /// Returns a value that indicates if the <paramref name="jsonAttribute"/> is <see cref="N"/>.
        /// </summary>
        /// <param name="jsonAttribute">The JSON attribute</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="N"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsN(string jsonAttribute)
        {
            return Equals(N, jsonAttribute);
        }


        /// <summary>
        /// Returns a value that indicates if the <paramref name="jsonAttribute"/> is <see cref="X"/>.
        /// </summary>
        /// <param name="jsonAttribute">The JSON attribute</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="X"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsX(string jsonAttribute)
        {
            return Equals(X, jsonAttribute);
        }


        /// <summary>
        /// Returns a value that indicates if the <paramref name="jsonAttribute"/> is <see cref="Y"/>.
        /// </summary>
        /// <param name="jsonAttribute">The JSON attribute</param>.
        /// <returns>
        /// <see langword="true" /> if the method is <see cref="Y"/>; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsY(string jsonAttribute)
        {
            return Equals(Y, jsonAttribute);
        }


        /// <summary>
        /// Returns the equivalent static instance, or the original instance if none match. This conversion is optional but allows for performance optimizations when comparing method values elsewhere.
        /// </summary>
        /// <param name="jsonAttribute"></param>
        /// <returns>The equivalent static instance of <paramref name="jsonAttribute"/>, or the original instance if none match.</returns>
        public static string GetCanonicalizedValue(string jsonAttribute) => jsonAttribute switch
        {
            string _ when IsCrv(jsonAttribute) => Crv,
            string _ when IsD(jsonAttribute) => D,
            string _ when IsE(jsonAttribute) => E,
            string _ when IsK(jsonAttribute) => K,
            string _ when IsKty(jsonAttribute) => Kty,
            string _ when IsN(jsonAttribute) => N,
            string _ when IsX(jsonAttribute) => X,
            string _ when IsY(jsonAttribute) => Y,
            string _ => jsonAttribute
        };


        /// <summary>
        /// Returns a value that indicates if the Crypto Suites are the same.
        /// </summary>
        /// <param name="jsonAttributeA">The first JSON attribute to compare.</param>
        /// <param name="jsonAttributeB">The first JSON attribute to compare.</param>
        /// <returns>
        /// <see langword="true" /> if the attributes are the same; otherwise, <see langword="false" />.
        /// </returns>
        public static bool Equals(string jsonAttributeA, string jsonAttributeB)
        {
            return object.ReferenceEquals(jsonAttributeA, jsonAttributeB) || StringComparer.OrdinalIgnoreCase.Equals(jsonAttributeA, jsonAttributeB);
        }
    }


    /// <summary>
    /// Xyz.
    /// </summary>
    public static class JwtUtilities
    {
        //The rules are from https://datatracker.ietf.org/doc/html/rfc7638#section-3.1.

        private static string ECTThumbprintTemplate => $@"{{{{""{JsonWebKeyThumbprintParameterNames.Crv}"":""{{0}}"",""{JsonWebKeyThumbprintParameterNames.Kty}"":""{{1}}"",""{JsonWebKeyThumbprintParameterNames.X}"":""{{2}}"",""{JsonWebKeyThumbprintParameterNames.Y}"":""{{3}}""}}}}";

        //https://datatracker.ietf.org/doc/html/rfc8037#appendix-A.3
        private static string EcdhTemplate => $@"{{{{""{JsonWebKeyThumbprintParameterNames.Crv}"":""{{0}}"",""{JsonWebKeyThumbprintParameterNames.Kty}"":""{{1}}"",""{JsonWebKeyThumbprintParameterNames.X}"":""{{2}}""}}}}";

        private static string RsaThumbprintTemplate => $@"{{{{""{JsonWebKeyThumbprintParameterNames.E}"":""{{0}}"",""{JsonWebKeyThumbprintParameterNames.Kty}"":""{{1}}"",""{JsonWebKeyThumbprintParameterNames.N}"":""{{2}}""}}}}";

        private static string OctThumbprintTemplate => $@"{{{{""{JsonWebKeyThumbprintParameterNames.K}"":""{{0}}"",""{JsonWebKeyThumbprintParameterNames.Kty}"":"" {{1}}""}}}}";


        public static byte[] ComputeECThumbprint(string crv, string kty, string x, string y)
        {
            var canonicalJwk = string.Format(ECTThumbprintTemplate, crv, kty, x, y);
            return GenerateSha256Hash(canonicalJwk);
        }

        public static byte[] ComputeEcdhThumbprint(string crv, string kty, string x)
        {
            //TODO: The parameters can be checked here too.
            var canonicalJwk = string.Format(EcdhTemplate, crv, kty, x);
            return GenerateSha256Hash(canonicalJwk);
        }

        public static byte[] ComputeRsaThumbprint(string e, string kty, string n)
        {
            var canonicalJwk = string.Format(RsaThumbprintTemplate, e, kty, n);
            return GenerateSha256Hash(canonicalJwk);
        }

        public static byte[] ComputeOctThumbprint(string k, string kty)
        {
            var canonicalJwk = string.Format(OctThumbprintTemplate, k, kty);
            return GenerateSha256Hash(canonicalJwk);
        }


        private static byte[] GenerateSha256Hash(string input)
        {
            return SHA256.HashData(Encoding.UTF8.GetBytes(input));
        }
    }


    public class DidKeyTestsTemp
    {
        /// <summary>
        /// Xyz.
        /// </summary>
        /// <param name="didDocumentFilename">The DID document data file under test.</param>
        /// <param name="didDocumentFileContents">The DID document data file contents.</param>
        /// <remarks>Compared to <see cref="CanRoundtripDidDocumentWithStronglyTypedService(string, string)"/>
        /// this tests without a provided strong type to see if <see cref="Service"/> is serialized.</remarks>
        [Theory]
        [FilesData(TestInfrastructureConstants.RelativeTestPathToCurrent, "did-key-1.json")]
        public void CanRoundtripDidKeyDocuments(string didDocumentFilename, string didDocumentFileContents)
        {
            TestInfrastructureConstants.ThrowIfPreconditionFails(didDocumentFilename, didDocumentFileContents);
            var options = new JsonSerializerOptions
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                PropertyNamingPolicy = new DefaultNamingNamingPolicy(Array.AsReadOnly(new JsonNamingPolicy[] { JsonNamingPolicy.CamelCase })),
                Converters =
            {
                new VerificationRelationshipConverterFactory(),
                new VerificationMethodConverter(),
                new ServiceConverterFactory(),
                new JsonLdContextConverter()
            }
            };

            DidDocument? deseserializedDidDocument = JsonSerializer.Deserialize<DidDocument>(didDocumentFileContents, options);
            _ = JsonSerializer.Serialize(deseserializedDidDocument, options);
        }
    }
}
