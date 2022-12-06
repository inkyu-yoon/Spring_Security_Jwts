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

    @Column(name = "user_account_id")
    private String userId;

    private String password;

    public User(UserJoinRequest userJoinRequest) {
        this.userId = userJoinRequest.getUserId();
        this.password = userJoinRequest.getPassword();
    }

}
