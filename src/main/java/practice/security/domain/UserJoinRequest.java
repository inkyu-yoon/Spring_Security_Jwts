package practice.security.domain;

import lombok.Getter;

@Getter

public class UserJoinRequest {

    private String userAccount;
    private String password;

    public User toEntity(String password) {
        return new User(this.userAccount, this.password);
    }

}
