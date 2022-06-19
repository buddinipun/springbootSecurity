package buddi.springboot.springsecuritydemo.security;

import buddi.springboot.springsecuritydemo.auth.ApplicationUserService;
import buddi.springboot.springsecuritydemo.jwt.JwtConfig;
import buddi.springboot.springsecuritydemo.jwt.JwtTokenVerifier;
import buddi.springboot.springsecuritydemo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;

import static buddi.springboot.springsecuritydemo.security.ApplicationUserRoles.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    private final ApplicationUserService applicationUserService;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;




    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService, SecretKey secretKey, JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

//authentication for request
    @Override
    protected void configure(HttpSecurity http) throws Exception {
       http
               .csrf().disable()
//               .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//               .and()
               .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
               .and()
              .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
               .addFilterAfter(new JwtTokenVerifier(jwtConfig, secretKey),JwtUsernameAndPasswordAuthenticationFilter.class)
              .authorizeHttpRequests()
               .antMatchers("/", "index", "/css/*", "js/*").permitAll()
               .antMatchers("/api/**").hasRole(STUDENT.name())
               .anyRequest()
               .authenticated();
//               .and()
//               //.httpBasic(); for basic authentication - basic auth login - without login form
//               .formLogin()
//                    .loginPage("/login")
//                    .permitAll()
//                    .defaultSuccessUrl("/courses",true)
//                    .passwordParameter("password")
//                     .usernameParameter("username")
//               .and().rememberMe()
//                        .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//                        .key("somethingverysecured")
//                        .rememberMeParameter("remember-me")
//               .and()
//               .logout()
//                        .logoutUrl("/logout")
//                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout","GET"))
//                        .clearAuthentication(true)
//                        .invalidateHttpSession(true)
//                        .deleteCookies("JSESSIONID", "remember-me")
//                        .logoutSuccessUrl("/login");
    }
// create user
//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//
//       UserDetails userbuddi =  User.builder()
//                .username("buddinipun")
//                .password(passwordEncoder.encode("password"))
//             //   .roles(STUDENT.name())
//               .authorities(STUDENT.getgrantedAuthorities())
//               .build();
//
//       UserDetails usernipun = User.builder()
//               .username("nipun")
//               .password(passwordEncoder.encode("password123"))
//              // .roles(ADMIN.name())
//               .authorities(ADMIN.getgrantedAuthorities())
//               .build();
//
//       UserDetails usertom = User.builder()
//               .username("tom")
//               .password(passwordEncoder.encode("password"))
//              // .roles(ADMINISTRATOR.name())
//               .authorities(ADMINISTRATOR.getgrantedAuthorities())
//               .build();

//       return new InMemoryUserDetailsManager(userbuddi,usernipun,usertom);


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
       auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
}
