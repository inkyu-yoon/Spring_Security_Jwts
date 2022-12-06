package practice.security.domain;

import lombok.Getter;

@Getter
public class UserJoinResponse {

    private String userAccount;

    public UserJoinResponse(User user) {
        this.userAccount = user.getUserAccount();
    }

}
