package com.uid2.attestation.azure;

import com.uid2.enclave.AttestationException;
import com.uid2.enclave.IAttestationProvider;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.HashMap;

public class AzureCCAttestationProvider implements IAttestationProvider {
	private final String maaEndpoint;
	private static final String DefaultMaaEndpoint = "sharedeus.eus.attest.azure.net";
	private final String skrEndpoint;
	private static final String DefaultSkrEndpoint = "http://localhost:8080/attest/maa";
	private final HttpClient httpClient;
	
	public AzureCCAttestationProvider() {
		this(DefaultSkrEndpoint, DefaultMaaEndpoint, null);
	}
	public AzureCCAttestationProvider(String maaEndpoint) {
		this(maaEndpoint, DefaultSkrEndpoint, null);
	}
	
	public AzureCCAttestationProvider(String maaEndpoint, String skrEndpoint) {
		this(maaEndpoint, skrEndpoint, null);
	}
	
	public AzureCCAttestationProvider(String maaEndpoint, String skrEndpoint, HttpClient httpClient) {
		this.maaEndpoint = maaEndpoint;
		this.skrEndpoint = skrEndpoint;
		
		if (httpClient != null) {
			this.httpClient = httpClient;
		} else {
			this.httpClient = HttpClient.newHttpClient();
		}
	}
	@Override
	public byte[] getAttestationRequest(byte[] publicKey) throws AttestationException {
		var base64Encoder = Base64.getEncoder();
		var gson = new Gson();
		
		var runtimeData = new HashMap<String, String>();
		runtimeData.put("location", getLocation());
		runtimeData.put("publicKey", base64Encoder.encodeToString(publicKey));
		String runtimeDataJson = gson.toJson(runtimeData);
		
		var body = new HashMap<String, String>();
		body.put("maa_endpoint", this.maaEndpoint);
		body.put("runtime_data", base64Encoder.encodeToString(runtimeDataJson.getBytes()));
		String bodyJson = gson.toJson(body);
		
		var request = HttpRequest.newBuilder()
				.uri(URI.create(skrEndpoint))
				.header("Content-Type", "application/json")
				.POST(HttpRequest.BodyPublishers.ofString(bodyJson))
				.build();

		try {
			HttpResponse<String> response = this.httpClient.send(request, HttpResponse.BodyHandlers.ofString());
			if (response.statusCode() != HttpURLConnection.HTTP_OK) {
				throw new AttestationException("Skr failed with status code: " + response.statusCode() + " body: " + response.body());
			}

			var responseBodyType = new TypeToken<HashMap<String, String>>(){};
			var responseBody = gson.fromJson(response.body(), responseBodyType);
			var token = responseBody.get("token");
			if (token == null) {
				throw new AttestationException("token field not exist in Skr response");
			}
			return token.getBytes();
		} catch (IOException e) {
			throw new AttestationException(e);
		} catch (InterruptedException e) {
			throw new AttestationException(e);
		}
	}
	
	private String getLocation() throws AttestationException {
		return "";
	}
}