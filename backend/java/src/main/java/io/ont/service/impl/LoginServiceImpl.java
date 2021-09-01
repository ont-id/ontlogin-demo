package io.ont.service.impl;

import com.alibaba.fastjson.JSONObject;
import com.github.ontio.modules.ClientHello;
import com.github.ontio.modules.ClientResponse;
import com.github.ontio.modules.ServerHello;
import io.ont.service.LoginService;
import io.ont.utils.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Service
@Slf4j
public class LoginServiceImpl implements LoginService {

    @Autowired
    private JWTUtils jwtUtils;
    @Autowired
    private SDKUtil sdkUtil;

    @Override
    public ServerHello generateChallenge(String action, ClientHello clientHello) throws Exception {
        return sdkUtil.generateChallenge(clientHello);
    }

    @Override
    public String validateClientResponse(String action, ClientResponse clientResponse) throws Exception {
        sdkUtil.validateClientResponse(clientResponse);
        String token = jwtUtils.signAccess("", "test user");
        return token;

    }

    @Override
    public void checkJwt(String action, String token) {
        jwtUtils.verifyAccessToken(token);
    }

}
