package com.uid2.attestation.azure;

import com.uid2.enclave.AttestationException;

import com.google.gson.Gson;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

import java.net.HttpURLConnection;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

public class AzureCCAttestationProviderTest {
    @Test
    public void testGetAttestationRequestSuccess() throws Exception {
        var gson = new Gson();
        
        // Mock response
        final var publicTokenMock = new byte[] {0x01, 0x02};
        final var maaTokenMock = "abc";
        final var httpResponseMock = mock(HttpResponse.class);
        when(httpResponseMock.statusCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(httpResponseMock.body()).thenReturn(gson.toJson(Map.of("token", maaTokenMock)));

        final var httpClientMock = mock(HttpClient.class);
        when(httpClientMock.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(httpResponseMock);
        
        // Verify output
        final var provider = new AzureCCAttestationProvider(AzureCCAttestationProvider.DefaultMaaEndpoint,
                AzureCCAttestationProvider.DefaultSkrEndpoint, httpClientMock);
        var output = provider.getAttestationRequest(publicTokenMock);
        Assert.assertArrayEquals(maaTokenMock.getBytes(), output);
        
        // Verify sent request
        var requestCaptor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClientMock).send(requestCaptor.capture(), any(HttpResponse.BodyHandler.class));
        var request = requestCaptor.getValue();
        Assert.assertEquals(AzureCCAttestationProvider.DefaultSkrEndpoint, request.uri().toString());
    }
    
    @Test
    public void testGetAttestationRequestFailure_InvalidStatusCode() throws Exception {
        final var publicTokenMock = new byte[] {0x01, 0x02};
        final var httpResponseMock = mock(HttpResponse.class);
        when(httpResponseMock.statusCode()).thenReturn(HttpURLConnection.HTTP_INTERNAL_ERROR);

        final var httpClientMock = mock(HttpClient.class);
        when(httpClientMock.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(httpResponseMock);

        final var provider = new AzureCCAttestationProvider(AzureCCAttestationProvider.DefaultMaaEndpoint,
                AzureCCAttestationProvider.DefaultSkrEndpoint, httpClientMock);
        var thrown = Assert.assertThrows(AttestationException.class, () -> provider.getAttestationRequest(publicTokenMock));
        Assert.assertTrue(thrown.getMessage().startsWith("Skr failed with status code: " + HttpURLConnection.HTTP_INTERNAL_ERROR));
    }
    
    @Test
    public void testGetAttestationRequestFailure_EmptyResponseBody() throws Exception {
        final var publicTokenMock = new byte[] {0x01, 0x02};
        final var httpResponseMock = mock(HttpResponse.class);
        when(httpResponseMock.statusCode()).thenReturn(HttpURLConnection.HTTP_OK);

        final var httpClientMock = mock(HttpClient.class);
        when(httpClientMock.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(httpResponseMock);

        final var provider = new AzureCCAttestationProvider(AzureCCAttestationProvider.DefaultMaaEndpoint,
                AzureCCAttestationProvider.DefaultSkrEndpoint, httpClientMock);
        var thrown = Assert.assertThrows(AttestationException.class, () -> provider.getAttestationRequest(publicTokenMock));
        Assert.assertEquals("response is null", thrown.getMessage());
    }

    @Test
    public void testGetAttestationRequestFailure_InvalidResponseBody() throws Exception {
        var gson = new Gson();
        final var publicTokenMock = new byte[] {0x01, 0x02};
        final var httpResponseMock = mock(HttpResponse.class);
        when(httpResponseMock.statusCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(httpResponseMock.body()).thenReturn(gson.toJson(Map.of("key", 123)));

        final var httpClientMock = mock(HttpClient.class);
        when(httpClientMock.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(httpResponseMock);

        final var provider = new AzureCCAttestationProvider(AzureCCAttestationProvider.DefaultMaaEndpoint,
                AzureCCAttestationProvider.DefaultSkrEndpoint, httpClientMock);
        var thrown = Assert.assertThrows(AttestationException.class, () -> provider.getAttestationRequest(publicTokenMock));
        Assert.assertEquals("token field not exist in Skr response", thrown.getMessage());
    }
}
