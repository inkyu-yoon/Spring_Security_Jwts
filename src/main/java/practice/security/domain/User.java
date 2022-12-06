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

    @Enumerated(EnumType.STRING)
    @Column(name = "user_Role")
    private UserRole userRole;

    public User(String userAccount, String password) {
        this.userAccount = userAccount;
        this.password = password;
        this.userRole = UserRole.USER;
    }

}
