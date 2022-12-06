package practice.security.domain;

import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Getter
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    @Column(name = "user_account")
    private String userAccount;

    private String password;

    public User(String userAccount, String password) {
        this.userAccount = userAccount;
        this.password = password;
    }

    public User(UserJoinRequest userJoinRequest) {
        this.userAccount = userJoinRequest.getUserAccount();
        this.password = userJoinRequest.getPassword();
    }

}
