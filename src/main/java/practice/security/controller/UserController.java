package practice.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import practice.security.domain.UserLoginRequest;
import practice.security.domain.UserLoginResponse;

@RestController
@RequestMapping("/api/v1")
public class UserController {

    @PostMapping("/login")
    public ResponseEntity<UserLoginResponse> getToken(@RequestBody UserLoginRequest userLoginRequest) {




    }
}
