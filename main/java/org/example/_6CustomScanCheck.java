package org.example;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.utilities.Utilities;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;


public class _6CustomScanCheck implements ScanCheck {
    MontoyaApi api;
    private byte[] serializationMagicBytes = {(byte)0xac, (byte)0xed, (byte)0x00, (byte)0x05};
    private byte[] base64MagicBytes = {(byte)0x72, (byte)0x4f, (byte)0x30, (byte)0x41};

    public _6CustomScanCheck(MontoyaApi api){
        this.api = api;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint){
        List<AuditIssue> activeAuditIssues = new ArrayList<AuditIssue>();
        for (int i=0;i<_6StaticItems.apacheCommonsCollections3Payloads.length;i++){
            HttpRequest commonsCollectionRequest = auditInsertionPoint.buildHttpRequestWithPayload(
                    ByteArray.byteArray(_6StaticItems.apacheCommonsCollections3Payloads[i]))
                    .withService(baseRequestResponse.httpService());
            long startTime = System.nanoTime();
            HttpRequestResponse commonsColletionResponse =  api.http().sendRequest(commonsCollectionRequest);
            long endTime = System.nanoTime();
            long duration = TimeUnit.SECONDS.convert((endTime - startTime), TimeUnit.NANOSECONDS);
            if ((int) duration > 9 ){
                AuditIssue auditIssue = AuditIssue.auditIssue(
                        _6StaticItems.apacheCommonsCollections3IssueName,
                        _6StaticItems.apacheCommonsCollections3IssueDetail,
                        null,
                        baseRequestResponse.request().url(),
                        _6StaticItems.apacheCommonsCollections3IssueSeverity,
                        _6StaticItems.apacheCommonsCollections3IssueConfidence,
                        null,
                        null,
                        _6StaticItems.apacheCommonsCollections3IssueTypicalSeverity,
                        commonsColletionResponse
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
                    _6StaticItems.passiveSerializationIssueName,
                    _6StaticItems.passiveSerializationIssueDetail,
                    null,
                    baseRequestResponse.request().url(),
                    _6StaticItems.passiveSerializationIssueSeverity,
                    _6StaticItems.passiveSerializationIssueConfidence,
                    null,
                    null,
                    _6StaticItems.passiveSerializationIssueTypicalSeverity,
                    baseRequestResponse.withRequestMarkers(highlights)
            );
            passiveAuditIssues.add(auditIssue);

        }
        return AuditResult.auditResult(passiveAuditIssues);
    }
}
