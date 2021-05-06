## Securing REST services and web applications with spring boot security starter

Security is one of the predominant aspects one must consider when developing any application or service.

For instance, we will implement spring security for the following API’s:

<ins><b>Student.java</b></ins>

```sh
@PostMapping(value = "/app1/spring-security/test")
public String testSpringSecurityForFirstApi() {
     return “You are authorised to use this First API”;
}

@PostMapping(value = "/app2/spring-security/test")
public String testSpringSecurityForSecondApi() {
     return “You are authorised to use this Second API”;
}
```

## 1. Add Spring boot starter dependency

```sh
Gradle:
compile('org.springframework.boot:spring-boot-starter-security')

Maven:
<dependency> 
<groupId>org.springframework.boot</groupId> 
<artifactId>spring-boot-starter-security</artifactId> 
</dependency>
```

## 2. Configure spring boot security:

We can configure spring security Authentication providers in multiple ways.
In this article, We will see configure it with two authentication providers:

### 1. An in-memory authentication provider.

In this case, we will store the username and password to be used during authentication in the properties(application.yml) file.

```sh
api.user.name: test
api.password: test
```
<i> We can directly use username and password in code instead of keeping in properties file but it is not a good practise as in future if it gets change then one need to make change in code which is not feasible for anyone other than developer.</i>

```sh
@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    public static final String ALL = "ALL";
    @Value("${api.user.name:@null}")
    private String userName;

    @Value("${api.password:@null}")
    private String password;

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {

        httpSecurity
                .antMatcher("/app1/spring-security/**")
                .antMatcher("/app2/spring-security/**")
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().and()
                .httpBasic();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser(userName).password(encoder().encode(password)).roles("ALL");
    }

    @Bean
    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }
}
```
* <b>WebSecurityConfigurerAdapter</b> allows customization to both WebSecurity and HttpSecurity.
* <b>antMatcher()</b> tells spring to only configure HttpSecurity if the path matches this pattern. That is it applies authorization to one or more paths.

<i>Due to security reasons we should NEVER store passwords in plain text format. It must be store in encrypted format. </i>
* <b>BCryptPasswordEncoder:</b> It is an implementation of Spring’s PasswordEncoder interface that uses the BCrypt strong hashing function to encode the password.

### 2. A custom authentication provider.
We will implement a custom authentication provider using <b>AuthenticationManagerBuilder</b>.

DB records :
username| password | user_role
test    | test     | admin

<b>UserDetailsServiceImpl.java </b>
It will implement UserDetailsService which locates user based on the username.

```sh
@Component
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private CredentialRepository credentialRepository;

    @Override
    public UserDetails loadUserByUsername(String username) {

        Credential user = credentialRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("User " + username + " not available");
        }
        GrantedAuthority authority = new SimpleGrantedAuthority(user.getRole());
        return new User(user.getUsername(),
                encoder().encode(user.getPassword()), Arrays.asList(authority));

    }

    BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }
}
```

<b>CredentialRepository.java</b>: It will fetch the user by username from DB.

```sh
@Repository
public interface CredentialRepository extends JpaRepository<Credential, UUID> {
   Credential findByUsername(String username);
}
```

<b>SecurityConfiguration.java</b>

```sh
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends  WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {

        httpSecurity
                .authorizeRequests()
                .antMatchers("/app1/spring-security/test")
                .hasAuthority("MIGRATE")
                .antMatchers("/app2/spring-security/test")
                .permitAll()
                .authenticated()
                .and()
                .formLogin().and()
                .httpBasic().and().csrf().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authProvider(userDetailsService));
    }

    @Bean
    public DaoAuthenticationProvider authProvider(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(encoder());
        return authProvider;
    }

    @Bean
    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }
}
```

* <b>UserDetailsService</b>: It is used as a User DAO.It is the strategy used by DaoAuthenticationProvider.
* requests matched against "<b> /app1/spring-security/test </b>” are fully accessible.
* requests matched against "<b> /app2/spring-security/test </b>" require a user to be authenticated and must be associated to the ADMIN role.


For any unauthorized access to the above API’s it will show the <b><i>401(Unauthorised)</i></b> error.
