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
	private final String maaEndpoint;
	public static final String DefaultMaaEndpoint = "sharedeus.eus.attest.azure.net";
	
	private final String skrEndpoint;
	public static final String DefaultSkrEndpoint = "http://localhost:8080/attest/maa";
	
	private final HttpClient httpClient;
	private String location;
	
	public AzureCCAttestationProvider() {
		this(DefaultSkrEndpoint, DefaultMaaEndpoint, null, null);
	}
	public AzureCCAttestationProvider(String maaEndpoint) {
		this(maaEndpoint, DefaultSkrEndpoint, null, null);
	}
	
	public AzureCCAttestationProvider(String maaEndpoint, String skrEndpoint) {
		this(maaEndpoint, skrEndpoint, null, null);
	}
	
	public AzureCCAttestationProvider(String maaEndpoint, String skrEndpoint, HttpClient httpClient) {
		this(maaEndpoint, skrEndpoint, httpClient, null);
	}
	
	public AzureCCAttestationProvider(String maaEndpoint, String skrEndpoint, HttpClient httpClient, String location) {
		this.maaEndpoint = maaEndpoint;
		this.skrEndpoint = skrEndpoint;
		
		if (httpClient != null) {
			this.httpClient = httpClient;
		} else {
			this.httpClient = HttpClient.newHttpClient();
		}
		
		if (location != null) {
			this.location = location;
		}
	}
	
	@Override
	public byte[] getAttestationRequest(byte[] publicKey) throws AttestationException {
		var base64Encoder = Base64.getEncoder();
		var gson = new Gson();
		
		var runtimeData = Map.of("location", getLocation(), "publicKey", base64Encoder.encodeToString(publicKey));
		String runtimeDataJson = gson.toJson(runtimeData);
		
		var skrRequest = new SkrRequest();
		skrRequest.maa_endpoint = this.maaEndpoint;
		skrRequest.runtime_data = base64Encoder.encodeToString(runtimeDataJson.getBytes());
		
		String requestBody = gson.toJson(skrRequest);
		var request = HttpRequest.newBuilder()
				.uri(URI.create(skrEndpoint))
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
			throw new AttestationException(e);
		} catch (InterruptedException e) {
			throw new AttestationException(e);
		}
	}
	
	private String getLocation() throws AttestationException {
		if (this.location != null) {
			return this.location;
		}
		
		// TODO(lun.wang) get location from meta server
		return "";
	}

	private static class SkrRequest {
		private String maa_endpoint;
		private String runtime_data;
	}

	private static class SkrResponse {
		private String token;
	}
}