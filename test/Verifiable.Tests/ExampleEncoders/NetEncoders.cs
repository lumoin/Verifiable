using Verifiable.Core.Did;

namespace Verifiable.Tests.ExampleEncoders
{
    /*

     //The problem with this function is that it to manufacture KeyFormat it may require multiple different encoder functions
     //such as P-256, P-358 and so on. So one type needed is ReadOnlySpanFunc<byte,byte> encodingFunction that takes key material
     //and returns the encoded data. So it wraps some library or platform function doing the work. THIS RESULT is then turned
     //into a string in some specific way. See NetEncoder class!
     */

    internal class NetEncoders
    {
        

        public KeyFormat CreateNistJwk()
        {
            //TODO: Should PublicKeyJwk be able to carry also private keys?
            var jwk = new PublicKeyJwk
            {
                /*
                 {
                    "id": "did:example:123#n4cQ-I_WkHMcwXBJa7IHkYu8CMfdNcZKnKsOrnHLpFs",
                    "type": "JsonWebKey2020",
                    "controller": "did:example:123",
                    "publicKeyJwk": {
                    "kty": "RSA",
                    "e": "AQAB",
                    "n": "omwsC1AqEk6whvxyOltCFWheSQvv1MExu5RLCMT4jVk9khJKv8JeMXWe3bWHatjPskdf2dlaGkW5QjtOnUKL742mvr4tCldKS3ULIaT1hJInMHHxj2gcubO6eEegACQ4QSu9LO0H-LM_L3DsRABB7Qja8HecpyuspW1Tu_DbqxcSnwendamwL52V17eKhlO4uXwv2HFlxufFHM0KmCJujIKyAxjD_m3q__IiHUVHD1tDIEvLPhG9Azsn3j95d-saIgZzPLhQFiKluGvsjrSkYU5pXVWIsV-B2jtLeeLC14XcYxWDUJ0qVopxkBvdlERcNtgF4dvW4X00EHj4vCljFw"
                },
                {
                    "id": "did:example:123#_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw",
                    "type": "JsonWebKey2020",
                    "controller": "did:example:123",
                    "publicKeyJwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
                        "y": "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4"
                    }
                }
                */

                //The key identifier. In did:key this is thumbprint(jwk)#Base64(x).
                Kid = "ABC-123",


                /* RSA. */
                Kty = "RSA",

                //As per definition the exponent used by did:key RSA keys is 65537.
                //https://w3c-ccg.github.io/did-method-key/#x2048-bit-modulus-public-exponent-65537
                //This seem to be the default parameter, though better to be explicit and secure about this.
                //ReadOnlySpan<byte> RsaExponent65537 = new byte[] { 0x01, 0x00, 0x01 };
                //This translates to "AQAB" in Base64.
                //var publicExponent_e = Base64UrlEncoder.Encode(RsaExponent65537.ToArray());
                E = "AQAB",

                //Exponent is fixed and not transmitted in key information so this too can be fixed. Write a better document about this.
                /*
                    RSA public modulus n.
                    RSA public exponent e.
                    RSA secret exponent d = e^-1 \bmod (p-1)(q-1).
                    RSA secret prime p.
                    RSA secret prime q with p < q.
                    Multiplicative inverse u = p^-1 \bmod q.
                 */

                /*
                 * This public modulus is basically this for a RSA key.            
                 */
                //And for a ECDSA key it is this.
                //This corresponds to the new byte[] { 0x02 }.Concat(prms256.Q.X!).ToArray(); part. I.e. compressed public key.
                //Note also there needs to be a way to handle compressed keys. Since DIDs always are, can it be assumed
                //when return value from a creator function has been received? Yes, so it looks like. It just so happens
                //the delegate that wraps .NET platforms needs to do "compression" explicitly as per programmer action.
                //Also links for the compression are good to be had? Maybe explicit code to "name" that function and so
                //useable across the different MS RSA implementations (and maybe other platforms, such as browser).
                //
                //This is also Base64 encoded byte array.
                N = string.Empty
            };

            return jwk;
        }
    }
}
