package com.costa.token.decipher;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;
import javax.xml.bind.DatatypeConverter;

import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.mule.api.MuleContext;

import com.costa.constants.IDMConstants;
import com.costa.enums.DMEnum;
import com.costa.exceptions.JWTDecipherException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

/**
 * 
 * @author Sravanthi Bhaskara
 *
 */

public class JWTDeHashMechanism implements IDMConstants {

	@Inject
	private MuleContext muleContext;

	private static final Logger logger = Logger.getLogger(JWTDeHashMechanism.class);

	/**
	 * This method decrypts App token and extracts claims from JWT
	 * 
	 * @param appToken
	 * @param hashSecretKey
	 * @param aesSharedKey
	 * @param dbPayload
	 * @param flowVars
	 * @return Apptoken JSON Object
	 * @throws JWTDecipherException
	 */
	public Object dehashAppToken(String appToken, String hashSecretKey, String aesSharedKey,
			Map<String, String> flowVars) throws JWTDecipherException {

		try {
			JSONObject appTokenMap = new JSONObject();
			
			// Trigger KMS unravel API
			Integer appTokenLength = Integer.parseInt(muleContext.getRegistry().get(APP_TOKEN_LENGTH).toString());

			if (appToken.length() > appTokenLength) {
				throw new Exception("Invalid App Token. Token exceeded maximum length");
			} else {
				String parseClaims = this.triggerKMSService(appToken, flowVars);

				Claims claims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(hashSecretKey))
						.parseClaimsJws(parseClaims).getBody();

				appTokenMap.put(DMEnum.type.toString(), claims.get(DMEnum.type.toString()));
				appTokenMap.put(DMEnum.version.toString(), claims.get(DMEnum.version.toString()));
				appTokenMap.put(DMEnum.datevalid.toString(), claims.get(DMEnum.datevalid.toString()));
			}
			return appTokenMap;
		} catch (Exception e) {

			logger.error("Exception in JWTDehashMechanism class: " + e);
			throw new JWTDecipherException(e);
		}

	}


	/**
	 * This method decrypts User token and extracts comarch auth tokens from JWT
	 * 
	 * @param userToken
	 * @param hashSecretKey
	 * @param aesSharedKey
	 * @param dbPayload
	 * @param flowVars
	 * @return UserToken JSON Object
	 * @throws JWTDecipherException
	 */
	public Object dehashUserToken(String userToken, String hashSecretKey, String aesSharedKey,
			Map<String, String> flowVars) throws JWTDecipherException {
		System.out.println("Test");
		try {
			Map<String, Object> appTokenMap = new HashMap<String, Object>();
			Integer userTokenLength = Integer.parseInt(muleContext.getRegistry().get(USER_TOKEN_LENGTH).toString());

			if (userToken.length() > userTokenLength) {
				throw new Exception("Invalid User Token. Token exceeded maximum length");
			} else {

				// Trigger KMS Unravel API
				String parseClaims = this.triggerKMSService(userToken, flowVars);
				System.out.println("JWT Token Claims : " + parseClaims);
				logger.debug("JWT Token Claims : " + parseClaims);

				// This line will throw an exception if it is not a signed JWS
				// (as expected)
				Claims claims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(hashSecretKey))
						.parseClaimsJws(parseClaims).getBody();

				logger.info("Expiration: " + claims.getExpiration());

				// Extract Comarch tokens from JWT
				String accessToken = claims.get(DMEnum.access_token.toString()) != null
						? claims.get(DMEnum.access_token.toString()).toString() : "";
				String refreshToken = claims.get(DMEnum.refresh_token.toString()) != null
						? claims.get(DMEnum.refresh_token.toString()).toString() : "";

				appTokenMap.put(DMEnum.access_token.toString(), accessToken);
				appTokenMap.put(DMEnum.refresh_token.toString(), refreshToken);
				appTokenMap.put(DMEnum.expirationDate.toString(), claims.getExpiration());

			}
			return appTokenMap;

		}

		catch (Exception e) {

			logger.error("Exception in JWTDehashMechanism class: " + e);
			throw new JWTDecipherException(e);
		}

	}

	/**
	 * This method calls KMS API
	 * 
	 * @param token
	 * @param flowVars
	 * @return
	 * @throws IOException
	 */
	private String triggerKMSService(String token, Map<String, String> flowVars) throws IOException {
		String kmsUrl = flowVars.get(KMS_DECRYPT_URL);
		String kmsQueryParams = flowVars.get(KMS_QUERY_PARAMS);
		String kmsContentType = flowVars.get(KMS_CONTENT_TYPE);
		String kmsHeaderSystem = flowVars.get(KMS_SYSTEM);
		String kmsHeaderLanguage = flowVars.get(KMS_LANGUAGE);
		String kmsRequestMethod = flowVars.get(METHOD);

		// Open HTTPS connection
  	   URL url = new URL(kmsUrl + kmsQueryParams);
		HttpURLConnection httpsConnection = (HttpURLConnection) url.openConnection();

		// Set header parameters
		httpsConnection.setDoOutput(true);
		httpsConnection.setRequestMethod(kmsRequestMethod);
		httpsConnection.setRequestProperty(CONTENT_TYPE, kmsContentType);
		httpsConnection.setRequestProperty(SYSTEM, kmsHeaderSystem);
		httpsConnection.setRequestProperty(LANGUAGE, kmsHeaderLanguage);

		OutputStream os = httpsConnection.getOutputStream();

		JSONObject cipherText = new JSONObject();
		cipherText.put(CIPHER_TEXT, token);

		os.write(cipherText.toString().getBytes(UTF_8));

		// Call KMS Unravel API
		StringBuilder responseSB = new StringBuilder();
		BufferedReader br = new BufferedReader(new InputStreamReader(httpsConnection.getInputStream()));

		String line;
		while ((line = br.readLine()) != null)
			responseSB.append(line);
		// Close streams
		br.close();
		os.close();

		JSONObject response = new JSONObject(responseSB.toString());
		return response.get(PLAIN_TEXT).toString();

	}

	public MuleContext getMuleContext() {
		return muleContext;
	}

	public void setMuleContext(MuleContext muleContext) {
		this.muleContext = muleContext;
	}
}
