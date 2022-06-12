package buddi.springboot.springsecuritydemo.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static buddi.springboot.springsecuritydemo.security.ApplicationUserPermission.*;

public enum ApplicationUserRoles {

    STUDENT(Sets.newHashSet()),
    ADMIN(Sets.newHashSet(COURSE_READ,COURSE_WRITE,STUDENT_READ,STUDENT_WRITE)),

    ADMINISTRATOR(Sets.newHashSet(COURSE_READ,STUDENT_READ));

    private final Set<ApplicationUserPermission> permission;

    ApplicationUserRoles(Set<ApplicationUserPermission> permission) {
        this.permission = permission;
    }

    public Set<ApplicationUserPermission> getPermission() {
        return permission;
    }


    public Set<SimpleGrantedAuthority> getgrantedAuthorities(){
        Set<SimpleGrantedAuthority> permissions = getPermission().stream()
                .map(permission -> new SimpleGrantedAuthority((permission.getPermissioons())))
                .collect(Collectors.toSet());

        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));

        return permissions;
    }

}
