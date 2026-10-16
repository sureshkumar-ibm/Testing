package com.wm.sqs;

// webMethods IS service infrastructure
import com.wm.data.IData;
import com.wm.data.IDataCursor;
import com.wm.data.IDataUtil;
import com.wm.app.b2b.server.ServiceException;

// AWS SDK v2
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

/**
 * webMethods Java Service: getTemporaryCredential
 *
 * Generic credential-fetch service.  Any IS flow calls this once to obtain
 * short-lived AWS session credentials via an X.509 client certificate and
 * AWS IAM Roles Anywhere.  The returned credentials (awsAccessKeyId,
 * awsSecretAccessKey, awsSessionToken) are plain pipeline Strings that can
 * be passed directly to readFromSQS, deleteFromSQS, or any other AWS
 * service that accepts pre-obtained session credentials.
 *
 * No IAM long-lived access keys are required anywhere.
 *
 * ─── Input pipeline variables ────────────────────────────────────────────────
 *  region           (String, required) AWS region, e.g. "us-east-1"
 *  trustAnchorArn   (String, required) ARN of the IAM Roles Anywhere Trust Anchor
 *  profileArn       (String, required) ARN of the IAM Roles Anywhere Profile
 *  roleArn          (String, required) IAM role ARN to assume
 *  roleSessionName  (String, optional) Session name tag — defaults to "wm-credential-session"
 *  keystorePath     (String, required) Filesystem path to the PKCS#12 (.p12/.pfx) keystore
 *  keystorePassword (String, required) Password for the PKCS#12 keystore
 *  tokenTtlSeconds  (String, optional) Session TTL in seconds: 900–3600 — default 3600
 *
 * ─── Output pipeline variables ───────────────────────────────────────────────
 *  awsAccessKeyId     (String) Temporary access key ID
 *  awsSecretAccessKey (String) Temporary secret access key
 *  awsSessionToken    (String) Session token — required alongside the temp key/secret
 *  credentialExpiry   (String) ISO-8601 expiry timestamp, e.g. "2025-06-01T12:00:00Z"
 */
public final class CredentialService {

    private CredentialService() {}

    /**
     * Entry point called by webMethods IS runtime.
     * Resolves X.509-backed temporary credentials and writes them to the pipeline.
     */
    public static final void getTemporaryCredential(IData pipeline) throws ServiceException {
        IDataCursor cursor = pipeline.getCursor();

        try {
            // ── Read inputs ──────────────────────────────────────────────────
            String region           = IDataUtil.getString(cursor, "region");
            String trustAnchorArn   = IDataUtil.getString(cursor, "trustAnchorArn");
            String profileArn       = IDataUtil.getString(cursor, "profileArn");
            String roleArn          = IDataUtil.getString(cursor, "roleArn");
            String roleSessionName  = IDataUtil.getString(cursor, "roleSessionName");
            String keystorePath     = IDataUtil.getString(cursor, "keystorePath");
            String keystorePassword = IDataUtil.getString(cursor, "keystorePassword");
            String tokenTtlStr      = IDataUtil.getString(cursor, "tokenTtlSeconds");

            // ── Validate required inputs ─────────────────────────────────────
            ServiceUtil.validateRequired("region",           region);
            ServiceUtil.validateRequired("trustAnchorArn",   trustAnchorArn);
            ServiceUtil.validateRequired("profileArn",       profileArn);
            ServiceUtil.validateRequired("roleArn",          roleArn);
            ServiceUtil.validateRequired("keystorePath",     keystorePath);
            ServiceUtil.validateRequired("keystorePassword", keystorePassword);

            // ── Apply defaults for optional inputs ───────────────────────────
            if (roleSessionName == null || roleSessionName.isEmpty()) {
                roleSessionName = "wm-credential-session";
            }
            int tokenTtlSeconds = ServiceUtil.parseIntOrDefault(tokenTtlStr, 3600);
            // Clamp to Roles Anywhere limits (900–3600 seconds)
            tokenTtlSeconds = Math.min(Math.max(tokenTtlSeconds, 900), 3600);

            // ── Resolve credentials via X.509 ────────────────────────────────
            // getProvider returns a cached, auto-refreshing provider.
            // resolveCredentials() triggers the actual CreateSession call on first
            // use or when the cached token is within 5 minutes of expiry.
            AwsSessionCredentials creds = (AwsSessionCredentials)
                    StsCredentialProviderHelper.getProvider(
                            region,
                            trustAnchorArn,
                            profileArn,
                            roleArn,
                            roleSessionName,
                            tokenTtlSeconds,
                            keystorePath,
                            keystorePassword)
                    .resolveCredentials();

            // ── Write credentials to pipeline ────────────────────────────────
            IDataUtil.put(cursor, "awsAccessKeyId",     creds.accessKeyId());
            IDataUtil.put(cursor, "awsSecretAccessKey", creds.secretAccessKey());
            IDataUtil.put(cursor, "awsSessionToken",    creds.sessionToken());
            // Expose expiry so the caller can decide whether to re-fetch
            IDataUtil.put(cursor, "credentialExpiry",
                    StsCredentialProviderHelper.getExpiryForProvider(
                            profileArn, roleArn, roleSessionName));

        } catch (ServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new ServiceException("getTemporaryCredential failed: " + e.getMessage(), e);
        } finally {
            cursor.destroy();
        }
    }

}
