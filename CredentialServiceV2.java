package com.wm.sqs;

// webMethods IS service infrastructure
import com.wm.data.IData;
import com.wm.data.IDataCursor;
import com.wm.data.IDataUtil;
import com.wm.app.b2b.server.ServiceException;

// AWS SDK v2
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

// Java security — types returned by pub.security.keystore:getKeyAndChain
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * webMethods Java Service: getTemporaryCredentialV2
 *
 * Obtains short-lived AWS session credentials via AWS IAM Roles Anywhere
 * using the aws4-x509-rsa-sha256 signing scheme.
 *
 * Unlike getTemporaryCredential (which reads a PKCS#12 keystore from disk),
 * this service accepts the private key and certificate chain as Java objects
 * directly from the webMethods IS built-in service:
 *
 *   pub.security.keystore:getKeyAndChain
 *     IN:  keystoreAlias, keyAlias, keyPassword
 *     OUT: privateKey       (java.security.PrivateKey)     — pass as-is
 *          certificateChain (java.security.cert.X509Certificate[]) — pass as-is
 *
 * The private key signs the Roles Anywhere CreateSession request directly
 * (RSA-SHA256) — no file I/O, no PKCS#12, no mTLS wiring required.
 *
 * ─── Input pipeline variables ────────────────────────────────────────────────
 *  region           (String,           required) AWS region, e.g. "us-east-1"
 *  trustAnchorArn   (String,           required) ARN of the Roles Anywhere Trust Anchor
 *  profileArn       (String,           required) ARN of the Roles Anywhere Profile
 *  roleArn          (String,           required) IAM role ARN to assume
 *  roleSessionName  (String,           optional) Session name tag — default: "wm-credential-session"
 *  tokenTtlSeconds  (String,           optional) Session TTL 900–3600 — default: 3600
 *  privateKey       (PrivateKey,       required) From pub.security.keystore:getKeyAndChain
 *  certificateChain (X509Certificate[],required) From pub.security.keystore:getKeyAndChain
 *
 * ─── Output pipeline variables ───────────────────────────────────────────────
 *  awsAccessKeyId     (String) Temporary access key ID
 *  awsSecretAccessKey (String) Temporary secret access key
 *  awsSessionToken    (String) Session token — required alongside temp key/secret
 *  credentialExpiry   (String) ISO-8601 expiry timestamp, e.g. "2025-06-01T12:00:00Z"
 *
 * ─── Typical IS flow ─────────────────────────────────────────────────────────
 *  1. pub.security.keystore:getKeyAndChain
 *       → privateKey, certificateChain
 *  2. SQSServices:getTemporaryCredentialV2
 *       → awsAccessKeyId, awsSecretAccessKey, awsSessionToken, credentialExpiry
 *  3. SQSServices:readFromSQS  (or deleteFromSQS, buildAwsHeaders)
 */
public final class CredentialServiceV2 {

    private CredentialServiceV2() {}

    /**
     * Entry point called by webMethods IS runtime.
     *
     * Reads the PrivateKey and X509Certificate[] Java objects directly from
     * the pipeline (put there by pub.security.keystore:getKeyAndChain) and
     * delegates to RolesAnywhereCredentialHelper to obtain session credentials.
     */
    public static final void getTemporaryCredentialV2(IData pipeline) throws ServiceException {
        IDataCursor cursor = pipeline.getCursor();

        try {
            // ── Read inputs ──────────────────────────────────────────────────
            String region          = IDataUtil.getString(cursor, "region");
            String trustAnchorArn  = IDataUtil.getString(cursor, "trustAnchorArn");
            String profileArn      = IDataUtil.getString(cursor, "profileArn");
            String roleArn         = IDataUtil.getString(cursor, "roleArn");
            String roleSessionName = IDataUtil.getString(cursor, "roleSessionName");
            String tokenTtlStr     = IDataUtil.getString(cursor, "tokenTtlSeconds");

            // These are Java objects placed in the pipeline by
            // pub.security.keystore:getKeyAndChain — read as Object, then cast.
            Object privateKeyObj   = IDataUtil.get(cursor, "privateKey");
            Object certChainObj    = IDataUtil.get(cursor, "certificateChain");

            // ── Validate required inputs ─────────────────────────────────────
            ServiceUtil.validateRequired("region",         region);
            ServiceUtil.validateRequired("trustAnchorArn", trustAnchorArn);
            ServiceUtil.validateRequired("profileArn",     profileArn);
            ServiceUtil.validateRequired("roleArn",        roleArn);

            if (privateKeyObj == null) {
                throw new ServiceException(
                        "Required input 'privateKey' is missing. " +
                        "Call pub.security.keystore:getKeyAndChain first.");
            }
            if (certChainObj == null) {
                throw new ServiceException(
                        "Required input 'certificateChain' is missing. " +
                        "Call pub.security.keystore:getKeyAndChain first.");
            }

            // ── Cast to Java security types ──────────────────────────────────
            PrivateKey privateKey;
            X509Certificate[] certChain;
            try {
                privateKey = (PrivateKey) privateKeyObj;
            } catch (ClassCastException e) {
                throw new ServiceException(
                        "'privateKey' is not a java.security.PrivateKey: "
                        + privateKeyObj.getClass().getName());
            }
            try {
                // pub.security.keystore:getKeyAndChain returns X509Certificate[]
                certChain = (X509Certificate[]) certChainObj;
            } catch (ClassCastException e) {
                throw new ServiceException(
                        "'certificateChain' is not a java.security.cert.X509Certificate[]: "
                        + certChainObj.getClass().getName());
            }
            if (certChain.length == 0) {
                throw new ServiceException("'certificateChain' is empty — at least one certificate is required.");
            }

            // ── Apply defaults for optional inputs ───────────────────────────
            if (roleSessionName == null || roleSessionName.isEmpty()) {
                roleSessionName = "wm-credential-session";
            }
            int tokenTtlSeconds = ServiceUtil.parseIntOrDefault(tokenTtlStr, 3600);
            tokenTtlSeconds = Math.min(Math.max(tokenTtlSeconds, 900), 3600);

            // ── Resolve credentials via private key signing ──────────────────
            // RolesAnywhereCredentialHelper caches the provider and auto-refreshes
            // 5 minutes before expiry.  The private key signs the CreateSession
            // request directly using RSA-SHA256 (aws4-x509-rsa-sha256 scheme).
            AwsSessionCredentials creds = (AwsSessionCredentials)
                    RolesAnywhereCredentialHelper.getProvider(
                            region,
                            trustAnchorArn,
                            profileArn,
                            roleArn,
                            roleSessionName,
                            tokenTtlSeconds,
                            privateKey,
                            certChain)
                    .resolveCredentials();

            // ── Write credentials to pipeline ────────────────────────────────
            IDataUtil.put(cursor, "awsAccessKeyId",     creds.accessKeyId());
            IDataUtil.put(cursor, "awsSecretAccessKey", creds.secretAccessKey());
            IDataUtil.put(cursor, "awsSessionToken",    creds.sessionToken());
            IDataUtil.put(cursor, "credentialExpiry",
                    RolesAnywhereCredentialHelper.getExpiry(profileArn, roleArn, roleSessionName));

        } catch (ServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new ServiceException("getTemporaryCredentialV2 failed: " + e.getMessage(), e);
        } finally {
            cursor.destroy();
        }
    }
}
