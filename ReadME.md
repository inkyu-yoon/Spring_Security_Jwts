

# 가장 간단한 모델로 구현하기

- [회원가입](#----)
    * [Response 클래스 구현](#Response 클래스 구현)
    * [Entity, DTO 구현](#-----dto---)
    * [Repository, Service 구현](#repository--service---)
    * [AppException 정의](#appexception---)
    * [BCryptPasswordEncoder](#bcryptpasswordencoder)
    * [Controller](#controller)
- [로그인 구현하기](#--------)
    * [DTO 준비](#dto---)
    * [JwtTokenUtil (토큰 생성기) 구현](#jwttokenutil------------)
    * [UserService 로그인 메서드 추가](#userservice-----------)
    * [Controller](#controller-1)
- [토큰으로 권한 부여하기](#------------)

<br>

# 회원가입

<br>

## Response 클래스 구현

```java
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class Response<T> {
    private String resultCode;
    private T result;

    public static Response<Void> error(String resultCode){
        return new Response(resultCode, null);
    }

    public static <T> Response<T> success(T result){
        return new Response<>("SUCCESS", result);
    }
}
```



> `.success()` 메서드로 `ResponseDto` 반환 시, "SUCCESS" 메세지와 `ResponseDto`가 JSON 형태로 응답받음

<br>

## Entity, DTO 구현

```java
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
}
```

> 회원 계정과 비밀번호만 입력받는 가장 간단한 엔티티이다.
>
> `userAccount` 와 `password` 를 매개변수로하는 생성자가 있는 이유는, `RequestDto` 에 있는 `passsword` 를 암호화 한 뒤
>
> `User` 객체를 암호화된 비밀번호로 초기화 한 뒤, DB에 넣기 위해

<br>


```java
import lombok.Getter;

@Getter
public class UserJoinRequest {

    private String userAccount;
    private String password;
}
```



> 회원 계정 명과 비밀번호만 POST 요청으로 받는다.

<br>


```java
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class UserJoinResponse {

    private String userAccount;
}
```

> 비밀번호는 응답하지 않고, 계정명만 응답한다.


<br>



## Repository, Service 구현

```java
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import practice.security.domain.User;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUserAccount(String userAccount);
}

```

> `JpaRepository`를 상속한 뒤, 사용자 계정명으로 찾는 메서드를 만든다.

<br>


```java
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
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

```

> `userRepository` 메서드로 가입 요청한 회원 계정명으로 찾아본 뒤, 이미 존재하면 `AppException` 이라는 사용자 정의 에러를 발생시킨다.
>
> 만약 없는 계정명이라면, `save` 로 DB에 저장한다.

<br>


## AppException 정의

```java
@Getter
@AllArgsConstructor
public class AppException extends RuntimeException {
    private ErrorCode errorCode;
}
```

> `ErrorCode` 라는 Enum 클래스만 갖고 있다.

<br>


 ```java
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum ErrorCode {
    DUPLICATED_USER_NAME(HttpStatus.CONFLICT, "user name is duplicated"),
    USER_NOT_FOUNDED(HttpStatus.NOT_FOUND, "not found error"),
    INVALID_PASSWORD(HttpStatus.BAD_REQUEST, "bad Request");

    private HttpStatus httpStatus;
    private String message;
}
 ```

> 나중에 `HttpStatus`는 `ResponseEntity` 를 구성할 때, 응답코드를 전달하기 위해 사용할 것이다.
>
> `message` 는 각 상황에 맞는 내용을 적어놓고, 응답화면으로 표시할 것이다.

<br>


```java
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ExceptionManager {

    @ExceptionHandler(AppException.class)
    public ResponseEntity<?> appExceptionHandler(AppException e) {
        return ResponseEntity.status(e.getErrorCode().getHttpStatus())
                .body(e.getErrorCode().getMessage());
    }
}
```

> `AppException.class` 예외가 발생하면 이 메서드를 실행시킨다.
>
> `ErrorCode`의 `HttpStatus` 와 `message` 를 이용해서 `status` 와 `body` 를 채워주면 된다.

<br>


## BCryptPasswordEncoder

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class EncryptorConfig {

    @Bean
    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }
}
```

> 암호화 및 암호 해독에 필요한 메서드를 갖고 있는 `BCryptPasswordEncoder` 클래스를 빈으로 등록한다.

<br>


## Controller

```java
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import practice.security.Service.UserService;
import practice.security.domain.Response;
import practice.security.domain.User;
import practice.security.domain.UserJoinRequest;
import practice.security.domain.UserJoinResponse;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final BCryptPasswordEncoder encoder;

    @PostMapping("/join")
    public Response<UserJoinResponse> join(@RequestBody UserJoinRequest userJoinRequest) {
        String encodedPassword = encoder.encode(userJoinRequest.getPassword());
        User user = new User(userJoinRequest.getUserAccount(), encodedPassword);
        userService.join(user);
        UserJoinResponse userJoinResponse = new UserJoinResponse(user.getUserAccount());

        return Response.success(userJoinResponse);
    }
}
```

> join POST 요청이 오면, 요청이 온**패스워드**는 암호화를 시킨 뒤, 저장한다. (나중에 해독할 수 있으니 암호화된 상태로 저장한다.)
>
> 정상적으로 회원가입이 완료되면, `Response.success()`로 응답한다.


<br>

---


# 로그인 구현하기

<br>

## DTO 준비

```java
import lombok.Getter;

@Getter
public class UserLoginRequest {

    private String userAccount;
    private String password;
}
```

> 로그인할 때, 아이디와 패스워드만 있으면 된다.

<br>

```java
import lombok.Getter;

@Getter
@AllArgsConstructor
public class UserLoginResponse {
    private String token;
}
```

> 응답은 암호화된 `JWT OAuth` 토큰으로 응답할 것이다.

<br>

## JwtTokenUtil (토큰 생성기) 구현

```yaml
jwt:
  token:
    secret: hello
```

> 토큰을 생성하기 위해서는, 사용자만 알고 있는 `secret key` 가 필요하다.
>
> 따라서 `application.yml` 에 위 구문을 추가하고 환경변수로 `JWT_TOKEN_SECRET=원하는 문자열` 을 등록한다.
>
> 참고로 문자열이 너무 짧으면 에러가 발생하므로 너무 짧게 하면 안된다.
>
> 등록한 환경변수는 `@Value("${jwt.token.secret}")` 어노테이션으로 주입시킬 수 있다.

<br>

```java
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Date;

public class JwtTokenUtil {
   private static long expiredTimeMs = 1000 * 60 * 60; //1시간
    
    public static String createToken(String userAccount, String key) {
        Claims claims = Jwts.claims();
        claims.put("userAccount", userAccount);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiredTimeMs))
                .signWith(SignatureAlgorithm.HS256, key)
                .compact();
    }
}
```

> 토큰을 만들기 위해서는 `Jwts`라는 클래스를 사용하고 `Claims` 라는 클래스에 정보를 집어넣고, 나중에 추출할 수 있다.
>
> `claims.put("userAccount", userAccount);` 를 통해서 로그인을 시도한 회원 계정을 토큰에 저장할 것이다.
>
> 이렇게 저장해두어야 나중에 토큰을 입력받았을 때, `userAccount` 를 추출해서 해당 아이디에 권한을 부여할 것이다.
>
> 만료시간은 1시간으로 설정하였다.

<br>

## UserService 로그인 메서드 추가

```JAVA
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import practice.security.domain.User;
import practice.security.exception.AppException;
import practice.security.exception.ErrorCode;
import practice.security.repository.UserRepository;
import practice.security.token.JwtTokenUtil;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder encoder;

    @Value("${jwt.token.secret}")
    private String secretKey;

    public User join(User user) {
        userRepository.findByUserAccount(user.getUserAccount())
                .ifPresent(user1 -> {
                    throw new AppException(ErrorCode.DUPLICATED_USER_NAME);
                });
        userRepository.save(user);

        return user;
    }

    public String login(String userAccount, String password) {
        User user = userRepository.findByUserAccount(userAccount)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUNDED));
        if (!encoder.matches(password, user.getPassword())) {
            throw new AppException(ErrorCode.INVALID_PASSWORD);
        }
        
        return JwtTokenUtil.createToken(userAccount,secretKey)
        
    }
}
```

> 먼저, 사용자에게 계정 명과, 암호화 되기 이전 비밀번호를 입력받을 것이다.
>
> 회원 계정명이 있는지 확인해보고, 없으면 예외처리를 한다.
>
> 회원 계정명이 있으면, 사용자가 입력한 암호와, 해당 계정명과 같이 DB에 저장되어 있는 암호화된 비밀번호가 같은지 `matches()` 메서드로 확인한다.
>
> 다르다면, 역시 예외처리를 한다.
>
> 정상적으로 통과 하였다면,`@Value("${jwt.token.secret}")` 로 secret key를 주입받고,  `createToken()` 메서드로 토큰을 생성한다.

<br>

## Controller

```java
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import practice.security.Service.UserService;
import practice.security.domain.*;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final BCryptPasswordEncoder encoder;

    @PostMapping("/join")
    public Response<UserJoinResponse> join(@RequestBody UserJoinRequest userJoinRequest) {
        String encodedPassword = encoder.encode(userJoinRequest.getPassword());
        User user = new User(userJoinRequest.getUserAccount(), encodedPassword);
        userService.join(user);
        UserJoinResponse userJoinResponse = new UserJoinResponse(user.getUserAccount());

        return Response.success(userJoinResponse);
    }

    @PostMapping("/login")
    public Response<UserLoginResponse> login(@RequestBody UserLoginRequest userLoginRequest) {
        String token = userService.login(userLoginRequest.getUserAccount(), userLoginRequest.getPassword());
        return Response.success(new UserLoginResponse(token));
    }
}
```

> 지금까지 `UserService`에 만든 메서드만 실행시켜서 token을 생성한 뒤, `UserLoginResponse` 객체에 토큰을 담은 뒤,
>
> `Response.success()` 메서드를 실행시키면 된다.

<br>

---

# 토큰으로 권한 부여하기




