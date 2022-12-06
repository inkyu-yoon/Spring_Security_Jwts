package practice.security.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import practice.security.domain.User;
import practice.security.domain.UserJoinRequest;
import practice.security.domain.UserLoginRequest;
import practice.security.domain.UserLoginResponse;
import practice.security.repository.UserRepository;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    @PostMapping("/join")
    public String getToken(@RequestBody UserJoinRequest userJoinRequest) {
        User user = new User(userJoinRequest);
        userRepository.save(user);
        return "회원가입이 완료되었습니다.";


    }
}
