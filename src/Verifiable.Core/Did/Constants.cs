namespace Verifiable.Core.Did
{
    /// <summary>
    /// Constants for various cryptographic algorithms used in
    /// decentralized identifiers and verifiable credentials.
    /// </summary>
    public static class CryptographyAlgorithmConstants
    {
        /// <summary>
        /// ECDH constants.
        /// </summary>
        public static class Ecdh
        {
            /// <summary>
            /// By definition, see at <see href="https://tools.ietf.org/html/rfc8037#section-2"/>.
            /// </summary>
            public const string KeyType = "OKP";

            /// <summary>
            /// By definition, see at <see href="https://tools.ietf.org/html/rfc8032#section-5.1.5"/>.
            /// </summary>
            public const int KeySizeInBytes = 32;

            public static class EdDsa
            {
                public const string Algorithm = "EdDSA";

                /// <summary>
                /// EdDSA key curves.
                /// </summary>
                public static class Curves
                {
                    //TODO: Add links to definitions as linked in https://tools.ietf.org/html/rfc8037#page-7.
                    public const string Ed25519 = "Ed25519";
                    public const string Ed448 = "Ed448";
                }
            }


            // https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2
            public static class EcdhEs
            {
                //https://datatracker.ietf.org/doc/html/rfc7748#section-6.1
                public static class Curves
                {
                    public const string X25519 = "X25519";
                    public const string X448 = "X448";
                }
            }
        }
    }
       

    /// <summary>
    /// This class holds some general constants as specified by DID Core specification.
    /// </summary>
    public static class DidCoreConstants
    {
        /// <summary>
        /// The DID documents must have a @context part in which the first URI is this.
        /// </summary>
        public const string JsonLdContextFirstUri = "https://www.w3.org/ns/did/v1";
    }
}
