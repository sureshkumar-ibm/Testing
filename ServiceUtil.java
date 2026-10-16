package com.wm.sqs;

import com.wm.app.b2b.server.ServiceException;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;

/**
 * Shared utility methods used across all IS Java Services in this package.
 * Centralises input validation, parsing, and SQS client construction
 * so those patterns are not duplicated across service classes.
 */
final class ServiceUtil {

    private ServiceUtil() {}

    /**
     * Throws {@link ServiceException} if {@code value} is null or blank.
     * Used by every IS Java Service to validate required pipeline inputs.
     */
    static void validateRequired(String name, String value) throws ServiceException {
        if (value == null || value.trim().isEmpty()) {
            throw new ServiceException("Required input '" + name + "' is missing or empty.");
        }
    }

    /**
     * Parses {@code value} as an int, returning {@code defaultValue} if the
     * string is null, empty, or non-numeric.
     * Used for optional numeric pipeline inputs (maxMessages, waitTimeSeconds, etc.).
     */
    static int parseIntOrDefault(String value, int defaultValue) {
        if (value == null || value.trim().isEmpty()) return defaultValue;
        try { return Integer.parseInt(value.trim()); }
        catch (NumberFormatException e) { return defaultValue; }
    }

    /**
     * Builds a one-shot {@link SqsClient} authenticated with pre-obtained
     * temporary session credentials.  The caller is responsible for closing
     * the client (use try-with-resources).
     *
     * @param region             AWS region string, e.g. "us-east-1"
     * @param awsAccessKeyId     Temporary access key from getTemporaryCredential
     * @param awsSecretAccessKey Temporary secret key from getTemporaryCredential
     * @param awsSessionToken    Session token from getTemporaryCredential
     */
    static SqsClient buildSqsClient(String region,
                                    String awsAccessKeyId,
                                    String awsSecretAccessKey,
                                    String awsSessionToken) {
        return SqsClient.builder()
                .region(Region.of(region))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsSessionCredentials.create(
                                awsAccessKeyId,
                                awsSecretAccessKey,
                                awsSessionToken)))
                .build();
    }
}
