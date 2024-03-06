/**
 * @author Giuseppe Valente <valente.1160073@uniroma1.it>
 */

package it.uniroma1.authenticationserver;


import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import it.uniroma1.authenticationserver.entities.User;
import it.uniroma1.authenticationserver.repositories.UserRepository;

@SpringBootTest
public class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Test
    public void testSaveUserInDB() {
        
        //Store and retrieve a user from DB
        User u = new User();
        u.setName("Giuseppe");
        u.setSurname("Verdi");
        u.setPassword("Ciao ciao");
        u.setEnabled(false);
        u.setEmail("giuseppe.verdi@email.it");
        u.setUsername(u.getName().substring(0, 4).concat(u.getSurname().substring(0, 4)));
        u = userRepository.save(u);
        
        // Retrieve data from the database
        User fromDb = userRepository.findByEmail(u.getEmail());
        assertTrue(fromDb.getEmail().equals(u.getEmail()));

        // Delete from the database the inserted user
        userRepository.delete(fromDb);

    }




}
