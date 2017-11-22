package com.costa.token.cipher;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Key;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.apache.log4j.Logger;
import org.json.JSONObject;

import com.costa.constants.IDMConstants;
import com.costa.enums.DMEnum;
import com.costa.exceptions.JWTCipherException;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * 
 * @author Sravanthi Bhaskara
 *
 */
public class JWTGenerateToken implements IDMConstants{

	private static final Logger logger = Logger.getLogger(JWTGenerateToken.class);

	/**
	 * This method generates KMS encrypted User JWT token including comarch tokens as claims
	 * @param sessionId
	 * @param sharedSecret
	 * @param aesKey
	 * @param refreshAfterTime
	 * @param expiryDateTime
	 * @param comarchToken
	 * @param flowVars
	 * @return
	 * @throws JWTCipherException
	 */
	public Object generateJWTToken(String sessionId, String sharedSecret,
			String aesKey,int refreshAfterTime, int expiryDateTime,Map<String,Object> comarchToken,Map<String, String> flowVars) throws JWTCipherException {

		try {

			SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

			// We will sign our JWT with our ApiKey secret
			byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(sharedSecret);
			Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());
			
			Integer expiresIn = comarchToken.get(DMEnum.expires_in.toString()) != null ? (Integer) comarchToken.get(DMEnum.expires_in.toString())
								: 0;
			
			Calendar cal = Calendar.getInstance();
			cal.add(Calendar.SECOND, expiresIn);
			
			logger.info("Expiry Date : " + expiresIn);
			
			Calendar calRefreshTime = Calendar.getInstance();
			calRefreshTime.add(Calendar.MONTH, refreshAfterTime);
			
			// Let's set the JWT Claims
			JwtBuilder builder = Jwts.builder().setId(UUID.randomUUID().toString()).setExpiration(cal.getTime())
					.claim(DMEnum.access_token.toString(), comarchToken.get(DMEnum.access_token.toString()))
					.claim(DMEnum.refresh_token.toString(), comarchToken.get(DMEnum.refresh_token.toString())).signWith(signatureAlgorithm, signingKey);
			builder.setExpiration(cal.getTime());
			DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
			TimeZone tz = TimeZone.getTimeZone("UTC");
			cal.setTimeZone(tz);
			
			String expiryDate = df.format(calRefreshTime.getTime());

			// Builds the JWT and serializes it to a compact, URL-safe string
			logger.debug(builder.compact());

			logger.info("Expiry Date : " + cal.getTime());

			String token = builder.compact();
			
			//Trigger KMS service
			String encryptedString = this.triggerKMSService(token, flowVars);
				      
			return encryptedString + "," + expiryDate;

		} catch (Exception e) {
			logger.error("Exception in JWTCipher class: " + e);
			throw new JWTCipherException(e);
		} 
	}
	
	/**
	 * This method generates KMS encrypted JWT App token
	 * @param type
	 * @param version
	 * @param date
	 * @param sharedSecret
	 * @param aesKey
	 * @param flowVars
	 * @return
	 * @throws JWTCipherException
	 */
	public Object generateToken( String type,String version, String date,
			String sharedSecret,
			String aesKey,Map<String, String> flowVars) throws JWTCipherException {

		try {

			SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

			// We will sign our JWT with our ApiKey secret
			byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(sharedSecret);
			Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

			Calendar cal = Calendar.getInstance();
			cal.add(Calendar.MONTH, Integer.parseInt(flowVars.get(DMEnum.appTokenExpiryDate.toString())));
			
			// Let's set the JWT Claims
			JwtBuilder builder = Jwts.builder().setId(UUID.randomUUID().toString()).setExpiration(cal.getTime())
					.claim(DMEnum.type.toString(), type)
					.claim(DMEnum.date.toString(), date)
					.claim(DMEnum.version.toString(), version)
					.signWith(signatureAlgorithm, signingKey);
			builder.setExpiration(cal.getTime());
			
			// Builds the JWT and serializes it to a compact, URL-safe string
			
			String token = builder.compact();

			// Trigger KMS Service
			String encryptedString = this.triggerKMSService(token, flowVars);

			
			return new org.json.JSONObject().put("token", encryptedString);

		} catch (Exception e) {
			logger.error("Exception in JWTCipher class: " + e);
			throw new JWTCipherException(e);
		} 
	}

	/**
	 * This method triggers KMS Inscribe API
	 * @param token
	 * @param flowVars
	 * @return
	 * @throws IOException
	 */
	private String triggerKMSService(String token, Map<String,String> flowVars) throws IOException{
		
		
		String kmsUrl = flowVars.get(KMS_ENCRYPT_URL);
		String kmsQueryParams = flowVars.get(KMS_QUERY_PARAMS);
		String kmsContentType = flowVars.get(KMS_CONTENT_TYPE);
		String kmsHeaderSystem = flowVars.get(KMS_SYSTEM);
		String kmsHeaderLanguage = flowVars.get(KMS_LANGUAGE);
		String kmsRequestMethod = flowVars.get(METHOD);
		
		//Open HTTPS connection
		URL url = new URL(kmsUrl + kmsQueryParams);
		HttpURLConnection httpsConnection = (HttpURLConnection) url.openConnection();
		
		//Set header parameters
		httpsConnection.setDoOutput(true);
		httpsConnection.setRequestMethod(kmsRequestMethod);
		httpsConnection.setRequestProperty(CONTENT_TYPE, kmsContentType);
		httpsConnection.setRequestProperty(SYSTEM, kmsHeaderSystem);
		httpsConnection.setRequestProperty(LANGUAGE, kmsHeaderLanguage);
		
		OutputStream os = httpsConnection.getOutputStream();
		
		JSONObject plainText = new JSONObject();
		plainText.put(PLAIN_TEXT, token);
		
		os.write(plainText.toString().getBytes(UTF_8));
		
		//Call KMS Inscribe API
		StringBuilder responseSB = new StringBuilder();
	    BufferedReader br = new BufferedReader(new InputStreamReader(httpsConnection.getInputStream()));
	          
        String line;
        while ( (line = br.readLine()) != null)
            responseSB.append(line);        
        // Close streams
        br.close();
        os.close();
        
        logger.debug("Encrypted text : " + responseSB);
        
        JSONObject response = new JSONObject(responseSB.toString());
		return response.get(CIPHER_TEXT).toString();
		
	}
}
