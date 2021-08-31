package io.ont.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.github.ontio.common.Helper;
import io.ont.exception.OntLoginException;
import io.ont.utils.myjwt.MyJwt;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
public class JWTUtils {

    @Autowired
    ConfigParam configParam;


    @Autowired
    private SDKUtil sdkUtil;

    private void verify(String token) {
        verifyWithPublicKey(token);
    }

    public void verifyWithPublicKey(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            String content = String.format("%s.%s", jwt.getHeader(), jwt.getPayload());
            String signature = jwt.getSignature();
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(Constant.SIGNATURE_KEY.getBytes(), "HmacSHA256");
            sha256_HMAC.init(secret_key);
            byte[] bytes = sha256_HMAC.doFinal(content.getBytes());
            String localSignature = Base64.encodeBase64URLSafeString(bytes);
            if (!localSignature.equals(signature)) {
                throw new OntLoginException("Verify token", ErrorInfo.VERIFY_TOKEN_FAILED.descEN(), ErrorInfo.VERIFY_TOKEN_FAILED.code());
            }

            if (jwt.getExpiresAt().before(new Date())) {
                throw new OntLoginException("Verify token", ErrorInfo.TOKEN_EXPIRED.descEN(), ErrorInfo.TOKEN_EXPIRED.code());
            }
        } catch (JWTDecodeException e) {
            throw new OntLoginException("Decode JWT error");
        } catch (OntLoginException e) {
            throw e;
        } catch (Exception e) {
            log.error("Verify with key error...", e);
            throw new OntLoginException("Token verify", ErrorInfo.VERIFY_TOKEN_FAILED.descEN(), ErrorInfo.VERIFY_TOKEN_FAILED.code());
        }
    }

    public void verifyAccessToken(String token) {
        if (!getContentType(token).equals(Constant.ACCESS_TOKEN)) {
            throw new OntLoginException("verify token", ErrorInfo.TOKEN_TYPE_ERROR.descEN(), ErrorInfo.TOKEN_TYPE_ERROR.code());
        }
        verify(token);
    }

    public String getContentUser(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return (String) jwt.getClaim("content").asMap().get("user");
        } catch (JWTDecodeException e) {
            e.printStackTrace();
            throw new OntLoginException("Decode JWT error");
        }
    }

    public String getContentType(String token) {
        try {
            if (token == null) {
                throw new OntLoginException("token is null");
            }
            DecodedJWT jwt = JWT.decode(token);
            return (String) jwt.getClaim("content").asMap().get("type");
        } catch (JWTDecodeException e) {
            e.printStackTrace();
            throw new OntLoginException("Decode JWT error");
        }
    }

    public String getAud(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim("aud").asString();
        } catch (JWTDecodeException e) {
            e.printStackTrace();
            throw new OntLoginException("Decode JWT error");
        }
    }


    public String signAccess(String aud, String user) throws Exception {
        HashMap<String, Object> contentData = new HashMap<>();
        contentData.put("type", Constant.ACCESS_TOKEN);
        contentData.put("user", user);

        return MyJwt.create().withIssuer("Demo Sever").withExpiresAt(new Date(new Date().getTime() + Constant.ACCESS_TOKEN_EXPIRE)).withAudience(aud).withIssuedAt(new Date()).
                withJWTId(UUID.randomUUID().toString().replace("-", "")).withClaim("content", contentData).sign(Constant.SIGNATURE_KEY);
    }


    public Map<String, Object> getContentApp(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim("app").asMap();
        } catch (JWTDecodeException e) {
            e.printStackTrace();
            throw new OntLoginException("Decode JWT error");
        }
    }


    public String getPayload(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getPayload();
        } catch (JWTDecodeException e) {
            e.printStackTrace();
            throw new OntLoginException("Decode JWT error");
        }
    }
}
