package buddi.springboot.springsecuritydemo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static buddi.springboot.springsecuritydemo.security.ApplicationUserPermission.*;
import static buddi.springboot.springsecuritydemo.security.ApplicationUserRoles.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

//authentication for request
    @Override
    protected void configure(HttpSecurity http) throws Exception {
       http
               .csrf().disable()
//               .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//               .and()
              .authorizeHttpRequests()
               .antMatchers("/", "index", "/css/*", "js/*").permitAll()
               .antMatchers("/api/**").hasRole(STUDENT.name())
               .anyRequest()
               .authenticated()
               .and()
               //.httpBasic(); for basic authentication
               .formLogin()
                    .loginPage("/login")
                    .permitAll()
                    .defaultSuccessUrl("/courses",true)
                    .passwordParameter("password")
                    .usernameParameter("username")
               .and().rememberMe()
                        .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                        .key("somethingverysecured")
                        .rememberMeParameter("remember-me")
               .and()
               .logout()
                        .logoutUrl("/logout")
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout","GET"))
                        .clearAuthentication(true)
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID", "remember-me")
                        .logoutSuccessUrl("/login");
    }
// create user
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {

       UserDetails userbuddi =  User.builder()
                .username("buddinipun")
                .password(passwordEncoder.encode("password"))
             //   .roles(STUDENT.name())
               .authorities(STUDENT.getgrantedAuthorities())
               .build();

       UserDetails usernipun = User.builder()
               .username("nipun")
               .password(passwordEncoder.encode("password123"))
              // .roles(ADMIN.name())
               .authorities(ADMIN.getgrantedAuthorities())
               .build();

       UserDetails usertom = User.builder()
               .username("tom")
               .password(passwordEncoder.encode("password"))
              // .roles(ADMINISTRATOR.name())
               .authorities(ADMINISTRATOR.getgrantedAuthorities())
               .build();

       return new InMemoryUserDetailsManager(userbuddi,usernipun,usertom);
    }
}
