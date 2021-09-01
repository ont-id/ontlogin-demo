package io.ont.service;


import com.alibaba.fastjson.JSONObject;
import com.github.ontio.modules.ClientHello;
import com.github.ontio.modules.ClientResponse;
import com.github.ontio.modules.ServerHello;

public interface LoginService {

    ServerHello generateChallenge(String action, ClientHello clientHello) throws Exception;

    String validateClientResponse(String action, ClientResponse clientResponse) throws Exception;

    void checkJwt(String action, String id);

}
