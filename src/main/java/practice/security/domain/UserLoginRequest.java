package practice.security.domain;

import lombok.Getter;

@Getter
public class UserLoginRequest {

    private String userId;
    private String password;
}
