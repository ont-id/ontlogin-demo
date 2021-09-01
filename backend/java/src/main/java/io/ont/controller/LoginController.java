package io.ont.controller;

import com.alibaba.fastjson.JSONObject;
import com.github.ontio.modules.ClientHello;
import com.github.ontio.modules.ClientResponse;
import com.github.ontio.modules.ServerHello;
import io.ont.bean.Result;
import io.ont.service.LoginService;
import io.ont.utils.ErrorInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/login")
@CrossOrigin
public class LoginController {
    @Autowired
    private LoginService loginService;

    @PostMapping("/challenge")
    public Result generateChallenge(@RequestBody ClientHello clientHello) throws Exception {
        String action = "generateChallenge";
        ServerHello result = loginService.generateChallenge(action, clientHello);
        return new Result(action, ErrorInfo.SUCCESS.code(), ErrorInfo.SUCCESS.descEN(), result);
    }

    @PostMapping("/validate")
    public Result validateClientResponse(@RequestBody ClientResponse clientResponse) throws Exception {
        String action = "validateClientResponse";
        String token = loginService.validateClientResponse(action, clientResponse);
        return new Result(action, ErrorInfo.SUCCESS.code(), ErrorInfo.SUCCESS.descEN(), token);
    }

    @PostMapping("/check-jwt")
    public Result checkJwt(@RequestBody JSONObject req) {
        String action = "checkJwt";
        String token = req.getString("token");
        loginService.checkJwt(action, token);
        return new Result(action, ErrorInfo.SUCCESS.code(), ErrorInfo.SUCCESS.descEN(), ErrorInfo.SUCCESS.descEN());
    }
}
