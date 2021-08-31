package io.ont.service.impl;

import com.alibaba.fastjson.JSONObject;
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
    public ServerHello generateChallenge(String action, JSONObject serverHello) throws Exception {
        return sdkUtil.generateChallenge();
    }

    @Override
    public String validateClientResponse(String action, ClientResponse clientResponse) throws Exception {
        sdkUtil.validateClientResponse(clientResponse);
        String token = jwtUtils.signAccess("", "test user");
        return token;

    }

    @Override
    public void checkJwt(String action, String token) throws Exception {
        jwtUtils.verifyAccessToken(token);
    }

}
