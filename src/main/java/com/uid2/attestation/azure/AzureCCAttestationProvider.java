package com.uid2.attestation.azure;

import com.uid2.enclave.AttestationException;
import com.uid2.enclave.IAttestationProvider;

import com.google.gson.Gson;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.Map;

public class AzureCCAttestationProvider implements IAttestationProvider {
	private final String maaServerBaseUrl;
	private static final String DefaultMaaServerBaseUrl = "https://sharedeus.eus.attest.azure.net";
	private final String maaEndpoint; // request param to SKR API which is parsed from maaServerBaseUrl
	
	private final String skrUrl;
	private static final String DefaultSkrUrl = "http://localhost:9000/attest/maa";
	
	private final HttpClient httpClient;
	private String location;
	
	public AzureCCAttestationProvider() {
		this(null, null, null, null);
	}

	public AzureCCAttestationProvider(String maaServerBaseUrl) {
		this(maaServerBaseUrl, null, null, null);
	}
	
	public AzureCCAttestationProvider(String maaServerBaseUrl, String skrUrl) {
		this(maaServerBaseUrl, skrUrl, null, null);
	}
	
	public AzureCCAttestationProvider(String maaServerBaseUrl, String skrUrl, HttpClient httpClient) {
		this(maaServerBaseUrl, skrUrl, httpClient, null);
	}
	
	/**
	 * Azure confidential container provider.
	 * Use SKR sidecar (https://github.com/microsoft/confidential-sidecar-containers) to get MAA token.
	 *
	 * @param maaServerBaseUrl attestation server base URL, e.g. https://sharedeus.eus.attest.azure.net, default url will be used if it's null
	 * @param skrUrl SKR sidecar API URL, default URL will be used if it's null
	 * @param httpClient new httpClient object will be created if it's null
	 * @param location deployment location, for testing
	 *
	 */
	public AzureCCAttestationProvider(String maaServerBaseUrl, String skrUrl, HttpClient httpClient, String location) {
		if (maaServerBaseUrl != null ) {
			this.maaServerBaseUrl = maaServerBaseUrl;
		} else {
			this.maaServerBaseUrl = DefaultMaaServerBaseUrl;
		}

		this.maaEndpoint = URI.create(this.maaServerBaseUrl).getHost();

		if (skrUrl != null) {
			this.skrUrl = skrUrl;
		} else {
			this.skrUrl = DefaultSkrUrl;
		}
		
		if (httpClient != null) {
			this.httpClient = httpClient;
		} else {
			this.httpClient = HttpClient.newHttpClient();
		}
		
		if (location != null) {
			this.location = location;
		} else {
			this.location = getLocation();
		}
	}
	
	@Override
	public byte[] getAttestationRequest(byte[] publicKey, byte[] userData) throws AttestationException {
		var base64Encoder = Base64.getEncoder();
		var gson = new Gson();
		
		var runtimeData = new RuntimeData();
		runtimeData.location = this.location;
		runtimeData.publicKey = base64Encoder.encodeToString(publicKey);
		runtimeData.userData = base64Encoder.encodeToString(userData);
		String runtimeDataJson = gson.toJson(runtimeData);

		var skrRequest = new SkrRequest();
		skrRequest.maa_endpoint = this.maaEndpoint;
		skrRequest.runtime_data = base64Encoder.encodeToString(runtimeDataJson.getBytes());
		
		String requestBody = gson.toJson(skrRequest);
		var request = HttpRequest.newBuilder()
				.uri(URI.create(this.skrUrl))
				.header("Content-Type", "application/json")
				.POST(HttpRequest.BodyPublishers.ofString(requestBody))
				.build();

		try {
			HttpResponse<String> response = this.httpClient.send(request, HttpResponse.BodyHandlers.ofString());
			if (response.statusCode() != HttpURLConnection.HTTP_OK) {
				throw new AttestationException("Skr failed with status code: " + response.statusCode() + " body: " + response.body());
			}

			var skrResponse = gson.fromJson(response.body(), SkrResponse.class);
			if (skrResponse == null) {
				throw new AttestationException("response is null");
			}
			
			if (skrResponse.token == null || skrResponse.token.isEmpty()) {
				throw new AttestationException("token field not exist in Skr response");
			}
			return skrResponse.token.getBytes();
		} catch (IOException e) {
			throw new AttestationException("failed to access Skr API: " + e.getMessage());
		} catch (InterruptedException e) {
			throw new AttestationException("failed to access Skr API: " + e.getMessage());
		}
	}
	
	private String getLocation() {
		// TODO(lun.wang) get location
		return "East US";
	}

	private static class RuntimeData {
		private String location;
		private String publicKey;
		private String userData;
	}

	private static class SkrRequest {
		private String maa_endpoint;
		private String runtime_data;
	}

	private static class SkrResponse {
		private String token;
	}
}