/**
 * @author Giuseppe Valente<valentepeppe@gmail.com>
 * Interface for roles
 */
package it.uniroma1.authenticationserver.repositories;

import org.springframework.data.repository.CrudRepository;

import it.uniroma1.authenticationserver.entities.Role;


public interface RoleRepository extends CrudRepository<Role, Long>{
    public Role findByAuthority(String authority);
}
