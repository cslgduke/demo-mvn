package com.example.demo;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.springframework.util.StringUtils;

import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * @author i565244
 */
@Slf4j
public class JwtMockUtil {

    private final static String TENANT_ID_HEADER = "X-Tenant-ID";
    private final static String TENANT_SCHEMA_HEADER = "X-Tenant-Schema";
    private final static String USERID_HEADER = "X-User-ID";
    private final static String AUTHORIZATION_HEADER = "Authorization";
    private final static String SCOPE = "scope";
    private final static String ISSUER = "https://dave-test.cslgduke.com/oauth/token";
    private final static String AUDIENCE = "ITCM";
    private final static String CID = "cid";
    private final static String CLIENT_ID = "client_id";
    private final static String EMAIL = "email";
    private final static String USER_ID = "user_id";
    private final static String SUBJECT = "user_id";

    private final static String USER_NAME = "user_name";

    private final static String ZID = "zid";
    private final static String BEARER = "Bearer ";
    private final static String DOT = ".";
    private final static String SCOPE_PREFIX = "data-privacy-integration-service!b000";
    private final static String GRANT_TYPE = "grant_type";


    static String secret = "MySecretMySecretMySecretMySecretMySecretMySecretMySecretMySecretMySecretMySecretMySecret";

    //jku
//    private final static String jkuUrl = "https://dave-test.cslgduke.com/oauth/token";

    private final static String jkuUrl = "https://dave-test-suu47312.authentication.us21.hana.ondemand.com/token_keys";


    interface GrantTypes {
        String AUTHORIZATION_CODE = "authorization_code";
        String CLIENT_CREDENTIALS = "client_credentials";
    }

    public static String mockJwt(List<String> scopes) {
        try {

            List<String> handledScope = scopes.stream().map(JwtMockUtil::preHandle).collect(Collectors.toList());

            // Generate an RSA key pair, which will be used for signing and verification of the JWT, wrapped in a JWK
            RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
            var pem = convertToPEM(rsaJsonWebKey.getPublicKey());
            saveToFile("publicKey.pem", pem);

            // Give the JWK a Key ID (kid), which is just the polite thing to do
            rsaJsonWebKey.setKeyId(UUID.randomUUID().toString().replace("-", "").toLowerCase());
            JwtClaims claims = new JwtClaims();
            claims.setIssuer(ISSUER);
            claims.setAudience(AUDIENCE);
            claims.setExpirationTimeMinutesInTheFuture(20);
            claims.setGeneratedJwtId();
            claims.setIssuedAtToNow();
            claims.setSubject("SUBJECT");
            claims.setClaim(SCOPE, handledScope);
            claims.setClaim(CID, "mock_client_id");
            claims.setClaim(CLIENT_ID, "mock_client_id");
            claims.setClaim(EMAIL, "mock@sap.com");
            claims.setClaim(USER_ID, "mock_user_id");
            claims.setClaim(USER_NAME, "mock_user");
            claims.setClaim(ZID, "mock_zid");
            claims.setClaim(GRANT_TYPE, GrantTypes.CLIENT_CREDENTIALS);

            claims.setGeneratedJwtId();
            JsonWebSignature jws = new JsonWebSignature();
            jws.setKey(rsaJsonWebKey.getPrivateKey());
            jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
            jws.setPayload(claims.toJson());
            var jwtToken = jws.getCompactSerialization();
            log.info("generate jwt using RSA-2048 :{}", jwtToken);

            return BEARER + jwtToken;
        } catch (JoseException e) {
            throw new RuntimeException("Fail to generate mock jwt token.", e);
        }
    }

    public static String mockJwtWithHS256() {

        try {
            // Define the secret key (must be at least 256 bits for HS256)
            Key key = Keys.hmacShaKeyFor(secret.getBytes());

            JwtClaims claims = new JwtClaims();

            claims.setGeneratedJwtId();
            claims.setIssuedAtToNow();
            claims.setSubject("SUBJECT");
            claims.setClaim("name", "John Doe");
            claims.setGeneratedJwtId();

            JsonWebSignature jws = new JsonWebSignature();
            jws.setKey(key);
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
            jws.setPayload(claims.toJson());
            var jwtToken = jws.getCompactSerialization();
            log.info("generate jwt using HMAC-SHA256 :{}", jwtToken);
            return jwtToken;
        } catch (JoseException e) {
            throw new RuntimeException("Fail to generate mock jwt token.", e);
        }
    }


    public static boolean validate(String jwtToken) {
        try {
            final String bearer = "Bearer";
            final String sysPropPayloadSkipVerify = "org.jose4j.jws.getPayload-skip-verify";

            if (StringUtils.startsWithIgnoreCase(jwtToken, bearer)) {
                jwtToken = jwtToken.replace("Bearer ", "");
            }
            var jws = new JsonWebSignature();
            jws.setCompactSerialization(jwtToken);
            //once setCompactSerialization, can't set alg again
//            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);// An entry for 'alg' already exists. Names must be unique.
            if (jws.getAlgorithm().getAlgorithmIdentifier().equals(AlgorithmIdentifiers.HMAC_SHA256)) {
                jws.setKey(Keys.hmacShaKeyFor((secret).getBytes()));
            } else if (jws.getAlgorithm().getAlgorithmIdentifier().equals(AlgorithmIdentifiers.RSA_USING_SHA256)) {
//                jws.setKey(loadPublicKey());
                jws.setKey(retrievePublicKey());
            }

            var verifySignature = jws.verifySignature();
            log.info("verifySignature result:{}", verifySignature);
            return verifySignature;
        } catch (JoseException e) {
            throw new RuntimeException("Fail to validate jwt token.", e);
        }
    }

    private static String preHandle(String preScope) {
        return SCOPE_PREFIX + DOT + preScope;
    }


    private static String convertToPEM(PublicKey publicKey) {
        String base64Encoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN PUBLIC KEY-----\n");
        pem.append(base64Encoded.replaceAll("(.{64})", "$1\n"));
        pem.append("\n-----END PUBLIC KEY-----");
        return pem.toString();
    }

    private static void saveToFile(String fileName, String content) {
        try (FileWriter writer = new FileWriter(fileName)) {
            writer.write(content);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static PublicKey loadPublicKey() {
        PublicKey publicKey = null;
        try {
            // Load the PEM file
            String pemFilePath = "publicKey.pem";
            String publicKeyPEM = new String(Files.readAllBytes(Paths.get(pemFilePath)));

            // Remove the PEM headers and footers
            publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replaceAll("\\s", "");

            // Decode the Base64 encoded string
            byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);

            // Convert the decoded bytes into an RSAPublicKey
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(spec);
        } catch (Exception e) {
            throw new RuntimeException("load publicKey failed", e);
        } finally {
            return publicKey;
        }
    }

    private static PublicKey retrievePublicKey() {
        PublicKey publicKey = null;
        try {
            InputStream is = new URL(jkuUrl).openStream();
            JWKSet jwkSet = JWKSet.load(is);
            JWK jwk = jwkSet.getKeys().get(0);
            if (jwk instanceof RSAKey) {
                // Convert JWK to RSAPublicKey
                publicKey = ((RSAKey) jwk).toPublicKey();
                log.info("Successfully loaded RSA public key:{} ",publicKey);

            } else {
                log.warn("The key is not an RSA key.");
            }

        } catch (Exception e) {
            throw new RuntimeException("retrieve publicKey failed", e);
        } finally {
            return publicKey;
        }
    }

    public static void main(String[] args) throws JoseException {
//        var jwtToken = mockJwtWithHS256();
//        validate(jwtToken);
//
//        jwtToken = mockJwt(List.of());
//        validate(jwtToken);

        var dpiToken = "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vZGF2ZS10ZXN0LXN1dTQ3MzEyLmF1dGhlbnRpY2F0aW9uLnVzMjEuaGFuYS5vbmRlbWFuZC5jb20vdG9rZW5fa2V5cyIsImtpZCI6ImRlZmF1bHQtand0LWtleS0tMTU1MzAyODkyMCIsInR5cCI6IkpXVCIsImppZCI6ICJiQmdvQ3FlcGsrRnFveXlZVm5aSWh5VUpiOWJ6akN5cUlXVWtkUG03aWo0PSJ9.eyJqdGkiOiI1NzVjMWI0ZWU1NzM0MmYzYjVjMTRhNjY5YzcxZmU0YSIsImV4dF9hdHRyIjp7ImVuaGFuY2VyIjoiWFNVQUEiLCJzdWJhY2NvdW50aWQiOiI0OTRlNjZhMi1jMmNiLTQ2NDMtODY1Zi1jYWNhZTkwYzA0ZGQiLCJ6ZG4iOiJkYXZlLXRlc3Qtc3V1NDczMTIiLCJzZXJ2aWNlaW5zdGFuY2VpZCI6IjNlYjM2NDg3LTNlNWYtNDM0OC1iYWQ0LTFjZGFjMzVhZThkYyJ9LCJzdWIiOiJzYi14c3VhYS1yZ20hYjgxOTZ8ZGF0YS1wcml2YWN5LWludGVncmF0aW9uLXNlcnZpY2UhYjc0OCIsImF1dGhvcml0aWVzIjpbImRhdGEtcHJpdmFjeS1pbnRlZ3JhdGlvbi1zZXJ2aWNlIWI3NDguT25ib2FyZGluZ1NlcnZpY2VTY29wZSIsInVhYS5yZXNvdXJjZSIsImRhdGEtcHJpdmFjeS1pbnRlZ3JhdGlvbi1zZXJ2aWNlIWI3NDguTW9uaXRvcmluZyIsImRhdGEtcHJpdmFjeS1pbnRlZ3JhdGlvbi1zZXJ2aWNlIWI3NDgubXRkZXBsb3ltZW50IiwiZGF0YS1wcml2YWN5LWludGVncmF0aW9uLXNlcnZpY2UhYjc0OC5EYXRhUHJpdmFjeUFwcGxpY2F0aW9uQ29ubmVjdG9yIl0sInNjb3BlIjpbInVhYS5yZXNvdXJjZSIsImRhdGEtcHJpdmFjeS1pbnRlZ3JhdGlvbi1zZXJ2aWNlIWI3NDguTW9uaXRvcmluZyIsImRhdGEtcHJpdmFjeS1pbnRlZ3JhdGlvbi1zZXJ2aWNlIWI3NDguRGF0YVByaXZhY3lBcHBsaWNhdGlvbkNvbm5lY3RvciIsImRhdGEtcHJpdmFjeS1pbnRlZ3JhdGlvbi1zZXJ2aWNlIWI3NDguT25ib2FyZGluZ1NlcnZpY2VTY29wZSIsImRhdGEtcHJpdmFjeS1pbnRlZ3JhdGlvbi1zZXJ2aWNlIWI3NDgubXRkZXBsb3ltZW50Il0sImNsaWVudF9pZCI6InNiLXhzdWFhLXJnbSFiODE5NnxkYXRhLXByaXZhY3ktaW50ZWdyYXRpb24tc2VydmljZSFiNzQ4IiwiY2lkIjoic2IteHN1YWEtcmdtIWI4MTk2fGRhdGEtcHJpdmFjeS1pbnRlZ3JhdGlvbi1zZXJ2aWNlIWI3NDgiLCJhenAiOiJzYi14c3VhYS1yZ20hYjgxOTZ8ZGF0YS1wcml2YWN5LWludGVncmF0aW9uLXNlcnZpY2UhYjc0OCIsImdyYW50X3R5cGUiOiJjbGllbnRfY3JlZGVudGlhbHMiLCJyZXZfc2lnIjoiNzc3OTcwMDQiLCJpYXQiOjE2ODI0MDQ2MDgsImV4cCI6MTY4MjQ0NzgwOCwiaXNzIjoiaHR0cHM6Ly9kYXZlLXRlc3Qtc3V1NDczMTIuYXV0aGVudGljYXRpb24udXMyMS5oYW5hLm9uZGVtYW5kLmNvbS9vYXV0aC90b2tlbiIsInppZCI6IjQ5NGU2NmEyLWMyY2ItNDY0My04NjVmLWNhY2FlOTBjMDRkZCIsImF1ZCI6WyJ1YWEiLCJkYXRhLXByaXZhY3ktaW50ZWdyYXRpb24tc2VydmljZSFiNzQ4Iiwic2IteHN1YWEtcmdtIWI4MTk2fGRhdGEtcHJpdmFjeS1pbnRlZ3JhdGlvbi1zZXJ2aWNlIWI3NDgiXX0.WYw0B871NRhruSO2ztn2sh1B-sktCpnAlINgxhSdw7Sp_njqT1-OISvKYfgvMMuMsLLPXctPl6TPExIXgmbI-jIf480DHNYRaDx_6DuvOzQwkq4qZ_STkhUavylXwXPc-O7z5U0E_Hfzu5PcicarPrdVSLPsF7nFggMtmKDzWvKFOcft77CeZ-iT_XvnAKOcGftxkXcpvzs5DjkNt3iCexX_HRb3Ec0aWt6jD-cMk-fnQGTHmgKC_C84MNTTdpYeB-e5JPyT7lQWgOmeOEPLndsPeFCD8bkRD6b8rS5cy0ToVfUIzaB_GzOcO26v54bLmvyHn1_qzggRbrMpS7m2Ig";
        validate(dpiToken);


    }


}
