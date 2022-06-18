package buddi.springboot.springsecuritydemo.auth;

import com.google.common.collect.Lists;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static buddi.springboot.springsecuritydemo.security.ApplicationUserRoles.*;
@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        passwordEncoder.encode("password"),
                        "annasmith",
                        STUDENT.getgrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),  new ApplicationUser(
                        passwordEncoder.encode("password"),
                        "linda",
                        ADMIN.getgrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),  new ApplicationUser(
                        passwordEncoder.encode("password"),
                        "tom",
                        ADMINISTRATOR.getgrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                )
        );
        return applicationUsers;
    }
}
