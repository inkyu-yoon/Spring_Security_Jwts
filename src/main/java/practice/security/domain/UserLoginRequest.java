package practice.security.domain;

import lombok.Getter;

@Getter
public class UserLoginRequest {

    private String userAccount;
    private String password;
}
