package com.wm.sqs;

// webMethods IS service infrastructure
import com.wm.data.IData;
import com.wm.data.IDataCursor;
import com.wm.data.IDataFactory;
import com.wm.data.IDataUtil;
import com.wm.app.b2b.server.ServiceException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

/**
 * webMethods Java Service: buildAwsHeaders
 *
 * Computes AWS Signature Version 4 (SigV4) signed HTTP headers for any AWS
 * REST/query API call using pre-obtained temporary session credentials.
 *
 * Typical flow:
 *   1. getTemporaryCredential  →  awsAccessKeyId, awsSecretAccessKey, awsSessionToken
 *   2. buildAwsHeaders         →  httpHeaders (IData with Authorization, X-Amz-Date,
 *                                              X-Amz-Security-Token, Host, Content-Type)
 *   3. Pass httpHeaders to any IS HTTP invoke (e.g. pub.client:http) to call AWS APIs
 *
 * ─── Input pipeline variables ────────────────────────────────────────────────
 *  awsAccessKeyId     (String, required) Temporary access key from getTemporaryCredential
 *  awsSecretAccessKey (String, required) Temporary secret key from getTemporaryCredential
 *  awsSessionToken    (String, required) Session token from getTemporaryCredential
 *  region             (String, required) AWS region, e.g. "us-east-1"
 *  service            (String, required) AWS service code, e.g. "sqs", "s3", "execute-api"
 *  method             (String, required) HTTP method: GET, POST, PUT, DELETE
 *  url                (String, required) Full request URL including query string
 *  requestBody        (String, optional) Request body — use empty string for GET/DELETE
 *  contentType        (String, optional) Content-Type header value.
 *                                        Default: "application/x-www-form-urlencoded"
 *
 * ─── Output pipeline variables ───────────────────────────────────────────────
 *  httpHeaders  (IData) Signed headers to attach to the outbound HTTP request:
 *                 Authorization      (String) AWS4-HMAC-SHA256 Credential=…,SignedHeaders=…,Signature=…
 *                 X-Amz-Date         (String) ISO-8601 compact timestamp, e.g. 20250601T120000Z
 *                 X-Amz-Security-Token (String) Session token — required for temp credentials
 *                 Host               (String) Hostname extracted from the URL
 *                 Content-Type       (String) Echo of the content-type used for signing
 */
public final class AwsHeaderService {

    private static final String ALGORITHM       = "AWS4-HMAC-SHA256";
    private static final String HMAC_ALGORITHM  = "HmacSHA256";
    private static final DateTimeFormatter DATE_TIME_FMT =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'");
    private static final DateTimeFormatter DATE_FMT =
            DateTimeFormatter.ofPattern("yyyyMMdd");

    private AwsHeaderService() {}

    /**
     * Entry point called by webMethods IS runtime.
     * Computes SigV4 Authorization header and companion headers.
     */
    public static final void buildAwsHeaders(IData pipeline) throws ServiceException {
        IDataCursor cursor = pipeline.getCursor();

        try {
            // ── Read inputs ──────────────────────────────────────────────────
            String awsAccessKeyId     = IDataUtil.getString(cursor, "awsAccessKeyId");
            String awsSecretAccessKey = IDataUtil.getString(cursor, "awsSecretAccessKey");
            String awsSessionToken    = IDataUtil.getString(cursor, "awsSessionToken");
            String region             = IDataUtil.getString(cursor, "region");
            String service            = IDataUtil.getString(cursor, "service");
            String method             = IDataUtil.getString(cursor, "method");
            String url                = IDataUtil.getString(cursor, "url");
            String requestBody        = IDataUtil.getString(cursor, "requestBody");
            String contentType        = IDataUtil.getString(cursor, "contentType");

            // ── Validate required inputs ─────────────────────────────────────
            ServiceUtil.validateRequired("awsAccessKeyId",     awsAccessKeyId);
            ServiceUtil.validateRequired("awsSecretAccessKey", awsSecretAccessKey);
            ServiceUtil.validateRequired("awsSessionToken",    awsSessionToken);
            ServiceUtil.validateRequired("region",             region);
            ServiceUtil.validateRequired("service",            service);
            ServiceUtil.validateRequired("method",             method);
            ServiceUtil.validateRequired("url",                url);

            // ── Apply defaults ────────────────────────────────────────────────
            if (requestBody == null) requestBody = "";
            if (contentType == null || contentType.isEmpty()) {
                contentType = "application/x-www-form-urlencoded";
            }
            method = method.toUpperCase();

            // ── Parse URL ─────────────────────────────────────────────────────
            URI uri         = URI.create(url);
            String host     = uri.getHost();
            String path     = (uri.getPath() == null || uri.getPath().isEmpty()) ? "/" : uri.getPath();
            String query    = (uri.getQuery() != null) ? uri.getQuery() : "";

            // ── Timestamps ────────────────────────────────────────────────────
            ZonedDateTime now      = ZonedDateTime.now(ZoneOffset.UTC);
            String amzDate         = now.format(DATE_TIME_FMT);   // 20250601T120000Z
            String dateStamp       = now.format(DATE_FMT);         // 20250601

            // ── Step 1: Canonical request ─────────────────────────────────────
            String payloadHash     = sha256Hex(requestBody);
            String canonicalHeaders =
                    "content-type:" + contentType + "\n" +
                    "host:"         + host        + "\n" +
                    "x-amz-date:"   + amzDate     + "\n" +
                    "x-amz-security-token:" + awsSessionToken + "\n";
            String signedHeaders = "content-type;host;x-amz-date;x-amz-security-token";

            String canonicalRequest = String.join("\n",
                    method,
                    canonicalUriEncode(path),
                    canonicalQueryString(query),
                    canonicalHeaders,
                    signedHeaders,
                    payloadHash);

            // ── Step 2: String to sign ────────────────────────────────────────
            String credentialScope = dateStamp + "/" + region + "/" + service + "/aws4_request";
            String stringToSign = String.join("\n",
                    ALGORITHM,
                    amzDate,
                    credentialScope,
                    sha256Hex(canonicalRequest));

            // ── Step 3: Signing key ───────────────────────────────────────────
            byte[] signingKey = deriveSigningKey(awsSecretAccessKey, dateStamp, region, service);

            // ── Step 4: Signature ─────────────────────────────────────────────
            String signature = toHex(hmacSHA256(signingKey, stringToSign));

            // ── Step 5: Authorization header ─────────────────────────────────
            String authorization = ALGORITHM
                    + " Credential=" + awsAccessKeyId + "/" + credentialScope
                    + ", SignedHeaders=" + signedHeaders
                    + ", Signature=" + signature;

            // ── Write output headers IData ────────────────────────────────────
            IData headers = IDataFactory.create();
            IDataCursor hc = headers.getCursor();
            IDataUtil.put(hc, "Authorization",          authorization);
            IDataUtil.put(hc, "X-Amz-Date",             amzDate);
            IDataUtil.put(hc, "X-Amz-Security-Token",   awsSessionToken);
            IDataUtil.put(hc, "Host",                    host);
            IDataUtil.put(hc, "Content-Type",            contentType);
            hc.destroy();

            IDataUtil.put(cursor, "httpHeaders", headers);

        } catch (ServiceException e) {
            throw e;
        } catch (Exception e) {
            throw new ServiceException("buildAwsHeaders failed: " + e.getMessage(), e);
        } finally {
            cursor.destroy();
        }
    }

    // -------------------------------------------------------------------------
    // SigV4 helpers
    // -------------------------------------------------------------------------

    /** SHA-256 hex digest of a UTF-8 string. */
    private static String sha256Hex(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return toHex(md.digest(data.getBytes(StandardCharsets.UTF_8)));
    }

    /** HMAC-SHA256 of a UTF-8 string with a raw byte key. */
    private static byte[] hmacSHA256(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    /** Derives the SigV4 signing key: kSecret → kDate → kRegion → kService → kSigning. */
    private static byte[] deriveSigningKey(String secret, String date,
                                           String region, String service) throws Exception {
        byte[] kSecret  = ("AWS4" + secret).getBytes(StandardCharsets.UTF_8);
        byte[] kDate    = hmacSHA256(kSecret,  date);
        byte[] kRegion  = hmacSHA256(kDate,    region);
        byte[] kService = hmacSHA256(kRegion,  service);
        return              hmacSHA256(kService, "aws4_request");
    }

    /** Converts a byte array to lowercase hex. */
    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /**
     * URI-encodes a path, preserving "/" segments.
     * AWS SigV4 requires each path segment to be percent-encoded but "/" kept as separator.
     */
    private static String canonicalUriEncode(String path) throws Exception {
        String[] segments = path.split("/", -1);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) sb.append('/');
            sb.append(URLEncoder.encode(segments[i], StandardCharsets.UTF_8.name())
                    .replace("+", "%20").replace("*", "%2A").replace("%7E", "~"));
        }
        return sb.toString();
    }

    /**
     * Sorts and encodes query parameters in canonical form required by SigV4.
     * Handles an already-encoded query string from the URL as-is after sorting.
     */
    private static String canonicalQueryString(String rawQuery) throws Exception {
        if (rawQuery == null || rawQuery.isEmpty()) return "";
        String[] pairs = rawQuery.split("&");
        java.util.TreeMap<String, String> sorted = new java.util.TreeMap<>();
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (eq >= 0) {
                sorted.put(pair.substring(0, eq), pair.substring(eq + 1));
            } else {
                sorted.put(pair, "");
            }
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : sorted.entrySet()) {
            if (sb.length() > 0) sb.append('&');
            sb.append(URLEncoder.encode(e.getKey(),   StandardCharsets.UTF_8.name())
                      .replace("+", "%20").replace("*", "%2A").replace("%7E", "~"))
              .append('=')
              .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8.name())
                      .replace("+", "%20").replace("*", "%2A").replace("%7E", "~"));
        }
        return sb.toString();
    }

}
