
keystoreAlias       String
keyAlias            String
trustAnchorArn      String
profileArn          String
roleArn             String
region              String
queueUrl            String
maxMessages         String   optional, default 10
waitTimeSeconds     String   optional, default 20
visibilityTimeout   String   optional
deleteAfterRead     String   optional, true/false, default false
roleSessionName     String   optional
durationSeconds     String   optional, default 3600

===============================
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import java.util.ArrayList;
import java.util.List;

import com.wm.app.b2b.server.Service;
import com.wm.app.b2b.server.ServiceException;
import com.wm.data.IData;
import com.wm.data.IDataCursor;
import com.wm.data.IDataFactory;
import com.wm.data.IDataUtil;

import software.amazon.awssdk.regions.Region;

import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.DeleteMessageRequest;
import software.amazon.awssdk.services.sqs.model.Message;
import software.amazon.awssdk.services.sqs.model.ReceiveMessageRequest;
import software.amazon.awssdk.services.sqs.model.ReceiveMessageResponse;

import software.amazon.rolesanywhere.plugin.RolesAnywherePlugin;
import software.amazon.rolesanywhere.plugin.X509Identity;
import software.amazon.rolesanywhere.plugin.X509IdentityProvider;


IDataCursor pipelineCursor = pipeline.getCursor();

String keystoreAlias =
    IDataUtil.getString(pipelineCursor, "keystoreAlias");

String keyAlias =
    IDataUtil.getString(pipelineCursor, "keyAlias");

String trustAnchorArn =
    IDataUtil.getString(pipelineCursor, "trustAnchorArn");

String profileArn =
    IDataUtil.getString(pipelineCursor, "profileArn");

String roleArn =
    IDataUtil.getString(pipelineCursor, "roleArn");

String regionName =
    IDataUtil.getString(pipelineCursor, "region");

String queueUrl =
    IDataUtil.getString(pipelineCursor, "queueUrl");

String maxMessagesString =
    IDataUtil.getString(pipelineCursor, "maxMessages");

String waitTimeSecondsString =
    IDataUtil.getString(pipelineCursor, "waitTimeSeconds");

String visibilityTimeoutString =
    IDataUtil.getString(pipelineCursor, "visibilityTimeout");

String deleteAfterReadString =
    IDataUtil.getString(pipelineCursor, "deleteAfterRead");

String roleSessionName =
    IDataUtil.getString(pipelineCursor, "roleSessionName");

String durationSecondsString =
    IDataUtil.getString(pipelineCursor, "durationSeconds");

pipelineCursor.destroy();

SqsClient sqsClient = null;

List<String> messageIdList = new ArrayList<String>();
List<String> messageBodyList = new ArrayList<String>();
List<String> receiptHandleList = new ArrayList<String>();
List<String> deletedMessageIdList = new ArrayList<String>();
List<IData> messageAttributeList = new ArrayList<IData>();

try {

    /*
     * ---------------------------------------------------------
     * 1. Validate mandatory inputs
     * ---------------------------------------------------------
     */

    if (keystoreAlias == null || keystoreAlias.trim().length() == 0) {
        throw new ServiceException("Input keystoreAlias is required.");
    }

    if (keyAlias == null || keyAlias.trim().length() == 0) {
        throw new ServiceException("Input keyAlias is required.");
    }

    if (trustAnchorArn == null || trustAnchorArn.trim().length() == 0) {
        throw new ServiceException("Input trustAnchorArn is required.");
    }

    if (profileArn == null || profileArn.trim().length() == 0) {
        throw new ServiceException("Input profileArn is required.");
    }

    if (roleArn == null || roleArn.trim().length() == 0) {
        throw new ServiceException("Input roleArn is required.");
    }

    if (regionName == null || regionName.trim().length() == 0) {
        throw new ServiceException("Input region is required.");
    }

    if (queueUrl == null || queueUrl.trim().length() == 0) {
        throw new ServiceException("Input queueUrl is required.");
    }

    int maxMessages = 10;
    int waitTimeSeconds = 20;
    int durationSeconds = 3600;

    Integer visibilityTimeout = null;

    if (maxMessagesString != null &&
        maxMessagesString.trim().length() > 0) {

        maxMessages = Integer.parseInt(maxMessagesString);
    }

    if (maxMessages < 1 || maxMessages > 10) {
        throw new ServiceException(
            "maxMessages must be between 1 and 10."
        );
    }

    if (waitTimeSecondsString != null &&
        waitTimeSecondsString.trim().length() > 0) {

        waitTimeSeconds = Integer.parseInt(waitTimeSecondsString);
    }

    if (waitTimeSeconds < 0 || waitTimeSeconds > 20) {
        throw new ServiceException(
            "waitTimeSeconds must be between 0 and 20."
        );
    }

    if (visibilityTimeoutString != null &&
        visibilityTimeoutString.trim().length() > 0) {

        visibilityTimeout =
            Integer.valueOf(visibilityTimeoutString);
    }

    if (durationSecondsString != null &&
        durationSecondsString.trim().length() > 0) {

        durationSeconds =
            Integer.parseInt(durationSecondsString);
    }

    boolean deleteAfterRead =
        "true".equalsIgnoreCase(deleteAfterReadString);

    if (roleSessionName == null ||
        roleSessionName.trim().length() == 0) {

        roleSessionName = "webMethods-IntegrationServer";
    }


    /*
     * ---------------------------------------------------------
     * 2. Invoke pub.security.keystore:getKeyAndChain
     * ---------------------------------------------------------
     */

    IData keystoreInput = IDataFactory.create();
    IDataCursor keystoreInputCursor =
        keystoreInput.getCursor();

    IDataUtil.put(
        keystoreInputCursor,
        "keystoreAlias",
        keystoreAlias
    );

    IDataUtil.put(
        keystoreInputCursor,
        "keyAlias",
        keyAlias
    );

    keystoreInputCursor.destroy();

    IData keystoreOutput = Service.doInvoke(
        "pub.security.keystore",
        "getKeyAndChain",
        keystoreInput
    );

    if (keystoreOutput == null) {
        throw new ServiceException(
            "pub.security.keystore:getKeyAndChain returned no output."
        );
    }

    IDataCursor keystoreOutputCursor =
        keystoreOutput.getCursor();

    Object privateKeyObject =
        IDataUtil.get(keystoreOutputCursor, "privateKey");

    Object certificateChainObject =
        IDataUtil.get(
            keystoreOutputCursor,
            "certificateChain"
        );

    keystoreOutputCursor.destroy();


    /*
     * ---------------------------------------------------------
     * 3. Validate and convert private key
     * ---------------------------------------------------------
     */

    if (privateKeyObject == null) {
        throw new ServiceException(
            "No privateKey was returned for key alias: " +
            keyAlias
        );
    }

    if (!(privateKeyObject instanceof PrivateKey)) {
        throw new ServiceException(
            "The returned privateKey is not a java.security.PrivateKey. " +
            "Returned type: " +
            privateKeyObject.getClass().getName()
        );
    }

    PrivateKey privateKey =
        (PrivateKey) privateKeyObject;


    /*
     * ---------------------------------------------------------
     * 4. Convert certificate chain
     * ---------------------------------------------------------
     */

    if (certificateChainObject == null) {
        throw new ServiceException(
            "No certificateChain was returned for key alias: " +
            keyAlias
        );
    }

    Certificate[] certificateChain;

    if (certificateChainObject instanceof Certificate[]) {

        certificateChain =
            (Certificate[]) certificateChainObject;

    } else if (certificateChainObject instanceof Object[]) {

        Object[] objects =
            (Object[]) certificateChainObject;

        certificateChain =
            new Certificate[objects.length];

        for (int i = 0; i < objects.length; i++) {

            if (!(objects[i] instanceof Certificate)) {
                throw new ServiceException(
                    "Invalid certificate object at chain index " +
                    i
                );
            }

            certificateChain[i] =
                (Certificate) objects[i];
        }

    } else {

        throw new ServiceException(
            "Unsupported certificateChain type: " +
            certificateChainObject.getClass().getName()
        );
    }

    if (certificateChain.length == 0) {
        throw new ServiceException(
            "The certificate chain is empty."
        );
    }

    if (!(certificateChain[0] instanceof X509Certificate)) {
        throw new ServiceException(
            "The leaf certificate is not an X509Certificate."
        );
    }

    X509Certificate leafCertificate =
        (X509Certificate) certificateChain[0];

    leafCertificate.checkValidity();


    /*
     * Prepare intermediate certificates.
     *
     * The first certificate is treated as the leaf/client
     * certificate. Remaining certificates are passed as the
     * intermediate chain.
     */

    List<X509Certificate> intermediateCertificates =
        new ArrayList<X509Certificate>();

    for (int i = 1; i < certificateChain.length; i++) {

        if (!(certificateChain[i] instanceof X509Certificate)) {
            throw new ServiceException(
                "Certificate at chain index " + i +
                " is not an X509Certificate."
            );
        }

        X509Certificate intermediate =
            (X509Certificate) certificateChain[i];

        intermediate.checkValidity();
        intermediateCertificates.add(intermediate);
    }


    /*
     * ---------------------------------------------------------
     * 5. Create Roles Anywhere X.509 identity
     * ---------------------------------------------------------
     *
     * Do not allow the plugin to destroy the IS-managed key.
     */

    X509Identity identity =
        X509Identity.createWithoutDestroyingKey(
            leafCertificate,
            privateKey,
            intermediateCertificates
        );

    X509IdentityProvider identityProvider =
        X509IdentityProvider.ofStatic(identity);


    /*
     * ---------------------------------------------------------
     * 6. Create IAM Roles Anywhere plugin
     * ---------------------------------------------------------
     */

    RolesAnywherePlugin plugin =
        RolesAnywherePlugin.builder()
            .identityProvider(identityProvider)
            .trustAnchorArn(trustAnchorArn)
            .profileArn(profileArn)
            .roleArn(roleArn)
            .roleSessionName(roleSessionName)
            .durationSeconds(durationSeconds)
            .region(Region.of(regionName))
            .build();


    /*
     * ---------------------------------------------------------
     * 7. Create Amazon SQS client
     * ---------------------------------------------------------
     */

    sqsClient =
        SqsClient.builder()
            .region(Region.of(regionName))
            .addPlugin(plugin)
            .build();


    /*
     * ---------------------------------------------------------
     * 8. Build SQS ReceiveMessage request
     * ---------------------------------------------------------
     */

    ReceiveMessageRequest.Builder receiveRequestBuilder =
        ReceiveMessageRequest.builder()
            .queueUrl(queueUrl)
            .maxNumberOfMessages(maxMessages)
            .waitTimeSeconds(waitTimeSeconds)
            .messageAttributeNames("All")
            .attributeNamesWithStrings("All");

    if (visibilityTimeout != null) {
        receiveRequestBuilder.visibilityTimeout(
            visibilityTimeout.intValue()
        );
    }

    ReceiveMessageResponse receiveResponse =
        sqsClient.receiveMessage(
            receiveRequestBuilder.build()
        );


    /*
     * ---------------------------------------------------------
     * 9. Process received messages
     * ---------------------------------------------------------
     */

    List<Message> messages =
        receiveResponse.messages();

    if (messages != null) {

        for (Message message : messages) {

            messageIdList.add(message.messageId());
            messageBodyList.add(message.body());
            receiptHandleList.add(message.receiptHandle());

            IData attributeDocument =
                IDataFactory.create();

            IDataCursor attributeCursor =
                attributeDocument.getCursor();

            IDataUtil.put(
                attributeCursor,
                "messageId",
                message.messageId()
            );

            IDataUtil.put(
                attributeCursor,
                "md5OfBody",
                message.md5OfBody()
            );

            IDataUtil.put(
                attributeCursor,
                "attributes",
                message.attributesAsStrings()
            );

            IDataUtil.put(
                attributeCursor,
                "messageAttributes",
                message.messageAttributes()
            );

            attributeCursor.destroy();

            messageAttributeList.add(attributeDocument);


        
