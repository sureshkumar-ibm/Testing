package com.wm.sqs;

import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.core.signer.Signer;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.rolesanywhere.RolesAnywhereClient;
import software.amazon.awssdk.services.rolesanywhere.model.CreateSessionRequest;
import software.amazon.awssdk.services.rolesanywhere.model.CreateSessionResponse;
import software.amazon.awssdk.services.rolesanywhere.model.CredentialSummary;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Helper that builds and caches credential providers using the
 * aws4-x509-rsa-sha256 signing scheme for AWS IAM Roles Anywhere.
 *
 * Unlike {@link StsCredentialProviderHelper}, this helper accepts a
 * {@link PrivateKey} and {@link X509Certificate}[] directly — exactly the
 * objects returned by the webMethods IS built-in service
 * {@code pub.security.keystore:getKeyAndChain}.  No keystore file path or
 * password is required.  The private key signs the CreateSession request
 * directly using RSA-SHA256 without any mTLS/file I/O.
 *
 * Typical IS flow:
 *   1. pub.security.keystore:getKeyAndChain  →  privateKey, certificateChain
 *   2. CredentialServiceV2.getTemporaryCredentialV2(privateKey, certificateChain, ...)
 *      →  awsAccessKeyId, awsSecretAccessKey, awsSessionToken, credentialExpiry
 *   3. readFromSQS / deleteFromSQS / buildAwsHeaders
 *
 * Required IAM Roles Anywhere resources:
 *   - A Trust Anchor registered with the CA that issued the client certificate
 *   - A Profile that maps the certificate to the target IAM role
 *   - The IAM role must trust the rolesanywhere.amazonaws.com service principal
 */
public final class RolesAnywhereCredentialHelper {

    // Cache providers keyed by profileArn#roleArn#sessionName
    private static final ConcurrentHashMap<String, WmX509CredentialsProvider> CACHE =
            new ConcurrentHashMap<>();

    private static final DateTimeFormatter DATE_TIME_FMT =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'");
    private static final DateTimeFormatter DATE_FMT =
            DateTimeFormatter.ofPattern("yyyyMMdd");

    private RolesAnywhereCredentialHelper() {}

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Returns a cached (or newly created) credential provider backed by the
     * supplied X.509 private key and certificate chain.
     *
     * <p>Credentials are refreshed automatically 5 minutes before expiry.
     *
     * @param region           AWS region, e.g. "us-east-1"
     * @param trustAnchorArn   ARN of the Roles Anywhere Trust Anchor
     * @param profileArn       ARN of the Roles Anywhere Profile
     * @param roleArn          ARN of the IAM role to assume
     * @param roleSessionName  Session name visible in CloudTrail
     * @param tokenTtlSeconds  Credential TTL in seconds: 900–3600
     * @param privateKey       Private key from pub.security.keystore:getKeyAndChain
     * @param certChain        Certificate chain from pub.security.keystore:getKeyAndChain
     * @return AwsCredentialsProvider backed by Roles Anywhere session credentials
     */
    public static AwsCredentialsProvider getProvider(
            String region,
            String trustAnchorArn,
            String profileArn,
            String roleArn,
            String roleSessionName,
            int tokenTtlSeconds,
            PrivateKey privateKey,
            X509Certificate[] certChain) {

        String cacheKey = profileArn + "#" + roleArn + "#" + roleSessionName;

        // Note: if the certificate is rotated, call invalidate() to force a new provider.
        return CACHE.computeIfAbsent(cacheKey, key -> new WmX509CredentialsProvider(
                region, trustAnchorArn, profileArn, roleArn,
                roleSessionName, tokenTtlSeconds, privateKey, certChain));
    }

    /**
     * Invalidates the cached provider so the next call to {@link #getProvider}
     * creates a fresh one with updated key/certificate material.
     */
    public static void invalidate(String profileArn, String roleArn, String roleSessionName) {
        CACHE.remove(profileArn + "#" + roleArn + "#" + roleSessionName);
    }

    /**
     * Returns the ISO-8601 expiry of the currently cached credentials,
     * or "UNKNOWN" if credentials have not been fetched yet.
     */
    public static String getExpiry(String profileArn, String roleArn, String roleSessionName) {
        WmX509CredentialsProvider p = CACHE.get(profileArn + "#" + roleArn + "#" + roleSessionName);
        if (p == null || p.expiresAt.equals(Instant.EPOCH)) return "UNKNOWN";
        return p.expiresAt.toString();
    }

    // =========================================================================
    // Inner provider — holds key material, calls CreateSession with SigV4-X509
    // =========================================================================

    /**
     * Credential provider that signs the Roles Anywhere CreateSession request
     * using the aws4-x509-rsa-sha256 scheme with the caller-supplied private key.
     * The certificate serial number and DER bytes are included in the signed headers
     * as required by the Roles Anywhere signing specification.
     */
    static final class WmX509CredentialsProvider implements AwsCredentialsProvider {

        private static final String ALGORITHM      = "AWS4-X509-RSA-SHA256";
        private static final String HMAC_ALG       = "HmacSHA256";
        private static final Duration REFRESH_BUF  = Duration.ofMinutes(5);

        private final String region;
        private final String trustAnchorArn;
        private final String profileArn;
        private final String roleArn;
        private final String roleSessionName;
        private final int tokenTtlSeconds;
        private final PrivateKey privateKey;
        private final X509Certificate[] certChain;

        volatile Instant expiresAt = Instant.EPOCH;
        private volatile AwsSessionCredentials cachedCredentials;

        WmX509CredentialsProvider(
                String region, String trustAnchorArn, String profileArn,
                String roleArn, String roleSessionName, int tokenTtlSeconds,
                PrivateKey privateKey, X509Certificate[] certChain) {
            this.region          = region;
            this.trustAnchorArn  = trustAnchorArn;
            this.profileArn      = profileArn;
            this.roleArn         = roleArn;
            this.roleSessionName = roleSessionName;
            this.tokenTtlSeconds = tokenTtlSeconds;
            this.privateKey      = privateKey;
            this.certChain       = certChain;
        }

        @Override
        public AwsCredentials resolveCredentials() {
            if (cachedCredentials == null ||
                    Instant.now().isAfter(expiresAt.minus(REFRESH_BUF))) {
                synchronized (this) {
                    if (cachedCredentials == null ||
                            Instant.now().isAfter(expiresAt.minus(REFRESH_BUF))) {
                        refresh();
                    }
                }
            }
            return cachedCredentials;
        }

        // ------------------------------------------------------------------
        // Signs the CreateSession request with aws4-x509-rsa-sha256 and
        // calls the Roles Anywhere endpoint.
        // ------------------------------------------------------------------
        private void refresh() {
            try {
                ZonedDateTime now   = ZonedDateTime.now(ZoneOffset.UTC);
                String amzDate      = now.format(DATE_TIME_FMT);   // 20250601T120000Z
                String dateStamp    = now.format(DATE_FMT);         // 20250601

                // Roles Anywhere endpoint
                String host         = "rolesanywhere." + region + ".amazonaws.com";
                String requestBody  = buildRequestBody();
                String payloadHash  = sha256Hex(requestBody);

                // Certificate serial number (decimal) — required header for X509 signing
                String certSerial   = certChain[0].getSerialNumber().toString();
                // DER-encoded leaf certificate — Base64 encoded, sent as X-Amz-X509 header
                String certDer      = Base64.getEncoder().encodeToString(certChain[0].getEncoded());

                // ── Canonical request ─────────────────────────────────────
                String canonicalHeaders =
                        "content-type:application/json\n" +
                        "host:" + host + "\n" +
                        "x-amz-date:" + amzDate + "\n" +
                        "x-amz-x509:" + certDer + "\n";
                String signedHeaders = "content-type;host;x-amz-date;x-amz-x509";

                String canonicalRequest = String.join("\n",
                        "POST",
                        "/sessions",
                        "",   // no query string
                        canonicalHeaders,
                        signedHeaders,
                        payloadHash);

                // ── Credential scope ──────────────────────────────────────
                String credentialScope = dateStamp + "/" + region + "/rolesanywhere/aws4_request";

                // ── String to sign ────────────────────────────────────────
                String stringToSign = String.join("\n",
                        ALGORITHM,
                        amzDate,
                        credentialScope,
                        sha256Hex(canonicalRequest));

                // ── Sign with RSA private key (aws4-x509-rsa-sha256) ──────
                // The X509 variant uses the private key directly (RSA-SHA256)
                // instead of the HMAC-based derived signing key.
                Signature rsaSig = Signature.getInstance("SHA256withRSA");
                rsaSig.initSign(privateKey);
                rsaSig.update(stringToSign.getBytes(StandardCharsets.UTF_8));
                String signature = toHex(rsaSig.sign());

                // ── Authorization header ──────────────────────────────────
                String authorization = ALGORITHM
                        + " Credential=" + certSerial + "/" + credentialScope
                        + ", SignedHeaders=" + signedHeaders
                        + ", Signature=" + signature;

                // ── Call Roles Anywhere CreateSession ─────────────────────
                // Use a no-credentials RolesAnywhereClient — we provide our own
                // pre-signed Authorization header via an ExecutionInterceptor.
                final String authHeader   = authorization;
                final String dateHeader   = amzDate;
                final String certHeader   = certDer;
                final String bodySnapshot = requestBody;

                RolesAnywhereClient client = RolesAnywhereClient.builder()
                        .region(Region.of(region))
                        .credentialsProvider(() -> AwsSessionCredentials.create("", "", ""))
                        .overrideConfiguration(cfg -> cfg.addExecutionInterceptor(
                                new ExecutionInterceptor() {
                                    @Override
                                    public SdkHttpFullRequest modifyHttpRequest(
                                            Context.ModifyHttpRequest ctx,
                                            ExecutionAttributes attrs) {
                                        return ctx.httpRequest().toBuilder()
                                                .putHeader("Authorization",  authHeader)
                                                .putHeader("X-Amz-Date",     dateHeader)
                                                .putHeader("X-Amz-X509",     certHeader)
                                                .build();
                                    }
                                }))
                        .build();

                CreateSessionRequest req = CreateSessionRequest.builder()
                        .trustAnchorArn(trustAnchorArn)
                        .profileArn(profileArn)
                        .roleArn(roleArn)
                        .sessionName(roleSessionName)
                        .durationSeconds(tokenTtlSeconds)
                        .build();

                CreateSessionResponse response;
                try (RolesAnywhereClient c = client) {
                    response = c.createSession(req);
                }

                if (response.credentialSet() == null || response.credentialSet().isEmpty()) {
                    throw new IllegalStateException(
                            "Roles Anywhere CreateSession returned no credentials.");
                }

                CredentialSummary cred = response.credentialSet().get(0).credentials();
                cachedCredentials = AwsSessionCredentials.create(
                        cred.accessKeyId(),
                        cred.secretAccessKey(),
                        cred.sessionToken());
                expiresAt = Instant.parse(cred.expiration());

            } catch (Exception e) {
                throw SdkClientException.create(
                        "RolesAnywhereCredentialHelper refresh failed: " + e.getMessage(), e);
            }
        }

        /** Builds the JSON body for CreateSession matching the Roles Anywhere REST API. */
        private String buildRequestBody() {
            // Roles Anywhere CreateSession POST /sessions body
            return "{" +
                    "\"durationSeconds\":" + tokenTtlSeconds + "," +
                    "\"profileArn\":\"" + profileArn + "\"," +
                    "\"roleArn\":\"" + roleArn + "\"," +
                    "\"sessionName\":\"" + roleSessionName + "\"," +
                    "\"trustAnchorArn\":\"" + trustAnchorArn + "\"" +
                    "}";
        }

        // ------------------------------------------------------------------
        // Crypto helpers
        // ------------------------------------------------------------------

        private static String sha256Hex(String data) throws Exception {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return toHex(md.digest(data.getBytes(StandardCharsets.UTF_8)));
        }

        private static String toHex(byte[] bytes) {
            StringBuilder sb = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) sb.append(String.format("%02x", b));
            return sb.toString();
        }
    }
}
