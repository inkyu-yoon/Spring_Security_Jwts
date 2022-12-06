package practice.security.Service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import practice.security.domain.User;
import practice.security.exception.AppException;
import practice.security.exception.ErrorCode;
import practice.security.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    public User join(User user) {
        userRepository.findByUserAccount(user.getUserAccount())
                .ifPresent(user1 -> {
                    throw new AppException(ErrorCode.DUPLICATED_USER_NAME);
                });
        userRepository.save(user);

        return user;

    }
}
