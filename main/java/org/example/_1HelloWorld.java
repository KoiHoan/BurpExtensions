package org.example;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;


public class _1HelloWorld implements BurpExtension {
    MontoyaApi api;
    Logging logging;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging=api.logging();
        api.extension().setName("HelloWorld");
        this.logging.logToOutput("*** Montoya API tutorial - Hello World loaded ***");

    }
}