

# 가장 간단한 엔티티 모델로 Spring Security & Token 인증 구현

- [회원가입](#----)
  * [Response 클래스 구현](#response)
  * [User Entity, DTO 구현](#entity-dto)
  * [Repository Service 구현](#repository-service)
  * [AppException 정의 및 구현](#appexception)
  * [BCryptPasswordEncoder 비밀번호 암호화](#bcryptpasswordencoder)
  * [Join Controller 회원가입 POST](#join-controller)
- [로그인 구현하기](#--------)
  * [로그인 DTO 구현](#dto)
  * [JwtTokenUtil Jwt 토큰 생성 클래스 구현](#jwttokenutil)
  * [UserService 로그인 메서드 추가](#userservice)
  * [Login Controller 로그인 POST](#login-controller)
- [토큰으로 권한 부여하기](#------------)
  * [UserSerivce 회원 계정으로 DB에서 찾는 메서드 추가](#userserivce-update)
  * [JwtTokenFilter 토큰 해독 및 권한 인증 필터 구현](#jwttokenfilter)
  * [Security Chain 필터 순서 변경 및 추가](#security-chain-update)
  * [기능 테스트](#user-controller-test)

<br>

# 회원가입

<br>

## Response

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

## Entity DTO

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

  @Enumerated(EnumType.STRING)
  @Column(name = "user_Role")
  private UserRole userRole;

  public User(String userAccount, String password) {
    this.userAccount = userAccount;
    this.password = password;
    this.userRole = UserRole.USER;
  }

}
```

> 회원 계정과 비밀번호만 입력받는 가장 간단한 엔티티이다.
>
> `userAccount` 와 `password` 를 매개변수로하는 생성자가 있는 이유는, `RequestDto` 에 있는 `passsword` 를 암호화 한 뒤
>
> `User` 객체를 암호화된 비밀번호로 초기화 한 뒤, DB에 넣기 위해 만들었다.
> 
> 'UserRole' 은 Enum 클래스이며, 기본값은 USER 로 부여한다.

<br>

```java
public enum UserRole {
    USER,ADMIN
}
```

> `UserRole` Enum 클래스는 위와 같다.

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



## Repository Service

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
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository userRepository;

    @Transactional
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


## AppException

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


## Join Controller

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

## DTO

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

## JwtTokenUtil


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
> HS256 알고리즘으로 암호화시키고, 토큰 만료시간은 1시간으로 설정하였다.

<br>

## UserService

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
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder encoder;

    @Value("${jwt.token.secret}")
    private String secretKey;
    
    @Transactional
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
        
        return JwtTokenUtil.createToken(userAccount,secretKey);
        
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

## Login Controller

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

<br>

## UserSerivce Update

```java
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import practice.security.domain.User;
import practice.security.exception.AppException;
import practice.security.exception.ErrorCode;
import practice.security.repository.UserRepository;
import practice.security.token.JwtTokenUtil;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder encoder;

    @Value("${jwt.token.secret}")
    private String secretKey;

    @Transactional
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

        return JwtTokenUtil.createToken(userAccount, secretKey);

    }

    public User getUserByUserAccount(String userAccount) {
        return userRepository.findByUserAccount(userAccount)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_FOUNDED));
    }
}
```

> 사용자 계정 명으로 User를 반환하는 메서드를 추가한다. 만약 없다면 예외처리를 한다.

<br>

## JwtTokenFilter

```java
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import practice.security.Service.UserService;
import practice.security.domain.User;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {

    private final UserService userService;
    private final String secretKey;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authorizationToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorizationToken == null || !authorizationToken.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        String token;
        try {
            token = authorizationToken.split(" ")[1];
        } catch (Exception e) {
            log.error("{} 에러가 발생하여 token 추출에 실패했습니다.",e);
            filterChain.doFilter(request, response);
            return;
        }

        if (JwtTokenFilter.isExpired(token, secretKey)) {
            filterChain.doFilter(request, response);
            return;
        }

        String userAccount = extractClaims(token,secretKey).get("userAccount").toString();
        User user = userService.getUserByUserAccount(userAccount);

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUserAccount(), null, List.of(new SimpleGrantedAuthority(user.getUserRole().name())));

        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        filterChain.doFilter(request, response);
    }

    private static Claims extractClaims(String token, String secretKey) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
    }

    public static boolean isExpired(String token, String secretKey) {
        Date expiredDate = extractClaims(token, secretKey).getExpiration();
        return expiredDate.before(new Date());
    }
}

```

> `JwtTokenFilter` 는 `OncePerRequestFilter` 를 상속받아서 구현한다. 보통 인증, 인가 과정은 이 필터를 상속받아서 사용한다.
>
> `HttpServletRequest` 의 요청에서 `AUTHORIZATION` 헤더 정보만 추출한 뒤, Null 이거나 Jwt 토큰이 아니라면 권한을 부여하기 전에 다음 필터로 이동시킨다.
>
> 토큰을 추출한 뒤, `secret Key`를 사용하여  `isExpired()` 메서드로 토큰이 만료되었는지 확인한다.
>
> 만료되지 않은 정상적인 Jwt 토큰이라면, 토큰을 생성할 때, 주입했었던 `userAccount` 데이터를 추출한 뒤, DB에서 찾아온다.
>
> 그리고 `UserRole` 을 get 한 뒤, 승인을 한다. (기본값은 "USER")
>
> 그다음 해당 계정을 승인했다는 정보를 `SecurityContextHolder` 에 담은 뒤, 다음 필터로 이동시킨다.

<br>

## Security Chain Update

```java
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import practice.security.Service.UserService;

@EnableWebSecurity
@RequiredArgsConstructor
public class HttpSecurityConfig {


    private final UserService userService;

    @Value("${jwt.token.secret}")
    private String secretKey;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .httpBasic().disable()
                .csrf().disable()
                .cors().and()
                .authorizeRequests()
                .antMatchers("api/v1/users/join", "/api/v1/users/login").permitAll()
                .antMatchers(HttpMethod.POST,"api/v1/**").authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilterBefore(new JwtTokenFilter(userService, secretKey), UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}

```

> join 과 login 요청은 항상 허용하고, 그 외 POST 요청은 권한을 확인한다.
>
> 그리고 `UsernamePasswordAuthenticationFilter` 를 지나가기전에 우리가 정의한 `JwtTokenFilter` 를 통과하도록 한다.

<br>

## User Controller Test

```java
package practice.security.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
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
@Slf4j
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

    @PostMapping("/hello")
    public String hello(@RequestBody UserLoginRequest userLoginRequest, Authentication authentication) {

        if (authentication.isAuthenticated()) {
            return "안녕";
        }
        return "실패";
    }
}
```

> `/hello` POST 메서드를 추가했고, 입력받은 토큰이 승인 권한 되었다면 "안녕"이 나오는지 확인해보겠다.

<br>

<p align="center">
<img src="https://raw.githubusercontent.com/buinq/imageServer/main/img/image-20221206173817941.png" alt="image-20221206173817941" style="zoom:67%;" />
</p>

> 회원가입을 진행했다.

<br>

<p align="center">

<img src="https://raw.githubusercontent.com/buinq/imageServer/main/img/image-20221206173847260.png" alt="image-20221206173847260" style="zoom:67%;" />
</p>

> 토큰을 발급 받기 전에 `/hello` POST 요청을 하니 에러가 발생한다.

<br>

<p align="center">

<img src="https://raw.githubusercontent.com/buinq/imageServer/main/img/image-20221206173906319.png" alt="image-20221206173906319" style="zoom:67%;" />
</p>

> `/login` POST 요청을 해서 토큰을 발급 받았다.

<br>

<p align="center">

<img src="https://raw.githubusercontent.com/buinq/imageServer/main/img/image-20221206173936178.png" alt="image-20221206173936178" style="zoom:67%;" />
</p>

> Authorization 설정에서 `OAuth 2.0` 타입으로 토큰을 담은 뒤 요청을 해보겠다.

<br>

<p align="center">

<img src="https://raw.githubusercontent.com/buinq/imageServer/main/img/image-20221206173958229.png" alt="image-20221206173958229" style="zoom:67%;" />
</p>

> 원하던, 안녕이라는 단어가 나왔다.



