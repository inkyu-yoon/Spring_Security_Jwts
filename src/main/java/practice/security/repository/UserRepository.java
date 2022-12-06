package practice.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import practice.security.domain.User;

public interface UserRepository extends JpaRepository<User,Long> {
}
