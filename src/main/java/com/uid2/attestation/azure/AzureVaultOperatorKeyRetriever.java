package com.uid2.attestation.azure;

import com.azure.identity.ManagedIdentityCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.google.common.base.Strings;
import com.uid2.enclave.IOperatorKeyRetriever;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AzureVaultOperatorKeyRetriever implements IOperatorKeyRetriever {
    private static final Logger LOGGER = LoggerFactory.getLogger(AzureVaultOperatorKeyRetriever.class);

    private final String vaultName;
    private final String secretName;

    public AzureVaultOperatorKeyRetriever(String vaultName, String secretName) {
        if (Strings.isNullOrEmpty(vaultName)) {
            throw new IllegalArgumentException("vaultName is null or empty");
        }
        if (Strings.isNullOrEmpty(secretName)) {
            throw new IllegalArgumentException("secretName is null or empty");
        }
        this.vaultName = vaultName;
        this.secretName = secretName;
    }

    // ManagedIdentityCredential is used here.
    @Override
    public String retrieve() {
        String vaultUrl = "https://" + this.vaultName + ".vault.azure.net";
        LOGGER.info(String.format("Load OperatorKey secret (%s) from %s", this.secretName, vaultUrl));
        // Use default ExponentialBackoff retry policy
        var secretClient = new SecretClientBuilder()
                .vaultUrl(vaultUrl)
                .credential(new ManagedIdentityCredentialBuilder().build())
                .buildClient();

        var retrievedSecret = secretClient.getSecret(secretName);

        LOGGER.info("OperatorKey secret is loaded.");
        return retrievedSecret.getValue();
    }
}
