package io.ont.utils.myjwt;

import com.auth0.jwt.impl.ClaimsHolder;
import com.auth0.jwt.impl.PayloadSerializer;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.github.ontio.account.Account;
import com.github.ontio.common.Helper;
import com.github.ontio.core.DataSignature;
import com.github.ontio.crypto.SignatureScheme;
import io.ont.exception.OntLoginException;
import io.ont.utils.Constant;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class MyJwtCreator {
    private final String headerJson;
    private final String payloadJson;


    private MyJwtCreator(Map<String, Object> headerClaims, Map<String, Object> payloadClaims) {


        try {
            ObjectMapper mapper = new ObjectMapper();
            SimpleModule module = new SimpleModule();
            module.addSerializer(ClaimsHolder.class, new PayloadSerializer());
            mapper.registerModule(module);
            mapper.configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true);
            this.headerJson = mapper.writeValueAsString(headerClaims);
            this.payloadJson = mapper.writeValueAsString(new ClaimsHolder(payloadClaims));
        } catch (JsonProcessingException var6) {
            throw new OntLoginException("Some of the Claims couldn't be converted to a valid JSON format : " + var6.getMessage());
        }
    }

    static MyJwtCreator.Builder init() {
        return new MyJwtCreator.Builder();
    }

    private String sign(String key) {
        String header = Base64.encodeBase64URLSafeString(this.headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = Base64.encodeBase64URLSafeString(this.payloadJson.getBytes(StandardCharsets.UTF_8));
        String content = String.format("%s.%s", header, payload);
        byte[] signatureBytes;
        try {
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(key.getBytes(), "HmacSHA256");
            sha256_HMAC.init(secret_key);
            signatureBytes = sha256_HMAC.doFinal(content.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            log.error("sign token error : {}" + e.getMessage());
            throw new OntLoginException("sign token error : " + e.getMessage());
        }
        String signature = Base64.encodeBase64URLSafeString(signatureBytes);
        log.info("sign,content:{},signature:{}", content, signature);
        return String.format("%s.%s", content, signature);
    }

    public static class Builder {
        private final Map<String, Object> payloadClaims = new HashMap();
        private Map<String, Object> headerClaims = new HashMap();

        Builder() {
        }

        public MyJwtCreator.Builder withHeader(Map<String, Object> headerClaims) {
            this.headerClaims = new HashMap(headerClaims);
            return this;
        }

        public MyJwtCreator.Builder withKeyId(String keyId) {
            this.headerClaims.put("kid", keyId);
            return this;
        }

        public MyJwtCreator.Builder withIssuer(String issuer) {
            this.addClaim("iss", issuer);
            return this;
        }

        public MyJwtCreator.Builder withSubject(String subject) {
            this.addClaim("sub", subject);
            return this;
        }

        public MyJwtCreator.Builder withAudience(String... audience) {
            this.addClaim("aud", audience);
            return this;
        }

        public MyJwtCreator.Builder withExpiresAt(Date expiresAt) {
            this.addClaim("exp", expiresAt);
            return this;
        }

        public MyJwtCreator.Builder withNotBefore(Date notBefore) {
            this.addClaim("nbf", notBefore);
            return this;
        }

        public MyJwtCreator.Builder withIssuedAt(Date issuedAt) {
            this.addClaim("iat", issuedAt);
            return this;
        }

        public MyJwtCreator.Builder withJWTId(String jwtId) {
            this.addClaim("jti", jwtId);
            return this;
        }

        public MyJwtCreator.Builder withClaim(String name, Boolean value) throws IllegalArgumentException {
            this.assertNonNull(name);
            this.addClaim(name, value);
            return this;
        }

        public MyJwtCreator.Builder withClaim(String name, Integer value) throws IllegalArgumentException {
            this.assertNonNull(name);
            this.addClaim(name, value);
            return this;
        }

        public MyJwtCreator.Builder withClaim(String name, Long value) throws IllegalArgumentException {
            this.assertNonNull(name);
            this.addClaim(name, value);
            return this;
        }

        public MyJwtCreator.Builder withClaim(String name, Double value) throws IllegalArgumentException {
            this.assertNonNull(name);
            this.addClaim(name, value);
            return this;
        }

        public MyJwtCreator.Builder withClaim(String name, String value) throws IllegalArgumentException {
            this.assertNonNull(name);
            this.addClaim(name, value);
            return this;
        }

        public MyJwtCreator.Builder withClaim(String name, Date value) throws IllegalArgumentException {
            this.assertNonNull(name);
            this.addClaim(name, value);
            return this;
        }

        public MyJwtCreator.Builder withClaim(String name, Object value) throws IllegalArgumentException {
            this.assertNonNull(name);
            this.addClaim(name, value);
            return this;
        }

        public MyJwtCreator.Builder withArrayClaim(String name, String[] items) throws IllegalArgumentException {
            this.assertNonNull(name);
            this.addClaim(name, items);
            return this;
        }

        public MyJwtCreator.Builder withArrayClaim(String name, Integer[] items) throws IllegalArgumentException {
            this.assertNonNull(name);
            this.addClaim(name, items);
            return this;
        }

        public MyJwtCreator.Builder withArrayClaim(String name, Long[] items) throws IllegalArgumentException {
            this.assertNonNull(name);
            this.addClaim(name, items);
            return this;
        }

        public String sign(String key) {
            this.headerClaims.put("alg", "HmacSHA256");
            this.headerClaims.put("typ", "JWT");

            return (new MyJwtCreator(this.headerClaims, this.payloadClaims)).sign(key);
        }

        private void assertNonNull(String name) {
            if (name == null) {
                throw new IllegalArgumentException("The Custom Claim's name can't be null.");
            }
        }

        private void addClaim(String name, Object value) {
            if (value == null) {
                this.payloadClaims.remove(name);
            } else {
                this.payloadClaims.put(name, value);
            }
        }
    }
}
