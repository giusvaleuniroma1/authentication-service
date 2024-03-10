/**
 * @author Giuseppe Valente <valente.1160073@uniroma1.it>
 */

package it.uniroma1.authenticationserver.repositories;

import org.springframework.data.repository.CrudRepository;

import it.uniroma1.authenticationserver.entities.User;

public interface UserRepository extends CrudRepository<User, Long>{

    public User findByEmail(String email);
    public User findByUsername(String username); 

}
