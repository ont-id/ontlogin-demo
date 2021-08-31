package io.ont.utils;

import com.github.ontio.OntLoginSdk;
import com.github.ontio.SDKConfig;
import com.github.ontio.did.DidProcessor;
import com.github.ontio.did.ont.OntProcessor;
import com.github.ontio.modules.*;
import io.ont.exception.OntLoginException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.*;


@Component
@Slf4j
public class SDKUtil {

    @Autowired
    private ConfigParam configParam;
    private OntLoginSdk sdk;
    private Map<String, Integer> nonceMap = new HashMap<>();

    private OntLoginSdk getOntLoginSdk() throws Exception {
        if (sdk == null) {
            synchronized (OntLoginSdk.class) {
                if (sdk == null) {
                    ServerInfo serverInfo = new ServerInfo();
                    serverInfo.setName("testServer");
                    serverInfo.setIcon("http://somepic.jpg");
                    serverInfo.setUrl("https://ont.io");
                    serverInfo.setDid("did:ont:AxxTest");
                    serverInfo.setVerificationMethod("did:ont:AxxTest");

                    SDKConfig sdkConfig = new SDKConfig();
                    sdkConfig.setChain(new String[]{"ont"});
                    sdkConfig.setAlg(new String[]{"ES256"});
                    sdkConfig.setServerInfo(serverInfo);

                    OntProcessor ontProcessor = new OntProcessor(false, "http://polaris2.ont.io:20334",
                            "52df370680de17bc5d4262c446f102a0ee0d6312", "./wallet.json", "12345678");
                    Map<String, DidProcessor> resolvers = new HashMap<>();
                    resolvers.put("ont", ontProcessor);

                    sdk = new OntLoginSdk(sdkConfig, resolvers) {
                        @Override
                        public String genRandomNonceFunc(Integer action) {
                            String nonce = UUID.randomUUID().toString().replace("-", "");
                            nonceMap.put(nonce, action);
                            return nonce;
                        }

                        @Override
                        public Integer getActionByNonce(String nonce) {
                            Integer action = nonceMap.get(nonce);
                            if (action == null) {
                                throw new OntLoginException("checkNonce", ErrorInfo.NONCE_NOT_EXISTS.descEN(), ErrorInfo.NONCE_NOT_EXISTS.code());
                            }
                            nonceMap.remove(nonce);
                            return action;
                        }
                    };
                }
            }
        }
        return sdk;
    }

    public ServerHello generateChallenge() throws Exception {
        ClientHello clientHello = new ClientHello();
        clientHello.setVer("1.0");
        clientHello.setType("ClientHello");
        clientHello.setAction(1);
        clientHello.setClientChallenge(new ClientChallenge());
        OntLoginSdk ontLoginSdk = getOntLoginSdk();
        ServerHello serverHello = ontLoginSdk.generateChallenge(clientHello);
        return serverHello;
    }

    public void validateClientResponse(ClientResponse clientResponse) throws Exception {
        OntLoginSdk ontLoginSdk = getOntLoginSdk();
        ontLoginSdk.validateClientResponse(clientResponse);
    }
}
