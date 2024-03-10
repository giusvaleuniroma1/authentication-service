package it.uniroma1.authenticationserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import it.uniroma1.authenticationserver.entities.User;
import it.uniroma1.authenticationserver.repositories.UserRepository;

@SpringBootTest
public class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    private User testUser;
    BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(); 

    /**
     * This method is called before each test marked as @Test
     */
    @BeforeEach
    public void setUp() {

        userRepository.deleteAll();
        //Create the test user 
        testUser = new User();
        testUser.setName("Freddy");
        testUser.setSurname("Jones");
        testUser.setEmail("freddy.jones@test.it");
        testUser.setUsername(testUser.getName().substring(0, 4) + testUser.getSurname().substring(0, 4));
        testUser.setPassword(bCryptPasswordEncoder.encode("HelloWorld!123"));
        testUser.setEnabled(true);

        userRepository.save(testUser);
    }

    @Test
    @SuppressWarnings("null")
    public void testUserInsert() {
        User savedUser = userRepository.findById(testUser.getId()).orElse(null);
        assertNotNull(savedUser);
        assertEquals(savedUser.getEmail(), testUser.getEmail());
        assertEquals(savedUser.getUsername(), testUser.getUsername());
    }

    @Test
    @SuppressWarnings("null")
    public void testUserWithSameUsername() {
        User savedUser = userRepository.findById(testUser.getId()).orElse(null);
        assertNotNull(savedUser);

        User u = new User();
        u.setName("Alice");
        u.setSurname("Jones");
        u.setEmail("alice.jones@test.it");
        u.setUsername(savedUser.getUsername());
        u.setPassword(bCryptPasswordEncoder.encode("HelloWorld!123"));
        u.setEnabled(true);
        assertThrows(DataIntegrityViolationException.class, () -> userRepository.save(u));
    }

    @Test
    @SuppressWarnings("null")
    public void testUserWithSameEmail() {
        User savedUser = userRepository.findById(testUser.getId()).orElse(null);
        assertNotNull(savedUser);
        User u = new User();
        u.setName("Alice");
        u.setSurname("Jones");
        u.setEmail(testUser.getEmail());
        u.setUsername(testUser.getName().substring(0, 4) + testUser.getSurname().substring(0, 4));
        u.setPassword(bCryptPasswordEncoder.encode("HelloWorld!123"));
        u.setEnabled(true);
        assertThrows(DataIntegrityViolationException.class, () -> userRepository.save(u));
    }

    @Test
    public void testNullName() {
        User u = new User();
        u.setName(null);
        u.setSurname("Jones");
        u.setEmail(testUser.getEmail());
        u.setUsername(testUser.getName().substring(0, 4) + testUser.getSurname().substring(0, 4));
        u.setPassword(bCryptPasswordEncoder.encode("HelloWorld!123"));
        u.setEnabled(true);
        assertThrows(DataIntegrityViolationException.class, () -> userRepository.save(u));
    }

    @Test
    public void testNullSurname() {
        User u = new User();
        u.setName("Alice");
        u.setSurname(null);
        u.setEmail(testUser.getEmail());
        u.setUsername(testUser.getName().substring(0, 4) + testUser.getSurname().substring(0, 4));
        u.setPassword(bCryptPasswordEncoder.encode("HelloWorld!123"));
        u.setEnabled(true);
        assertThrows(DataIntegrityViolationException.class, () -> userRepository.save(u));
    }

    @Test
    public void testNullEmail() {
        User u = new User();
        u.setName("Alice");
        u.setSurname("Jones");
        u.setEmail(null);
        u.setUsername(testUser.getName().substring(0, 4) + testUser.getSurname().substring(0, 4));
        u.setPassword(bCryptPasswordEncoder.encode("HelloWorld!123"));
        u.setEnabled(true);
        assertThrows(DataIntegrityViolationException.class, () -> userRepository.save(u));
    }

    @Test
    public void testNullUsername() {
        User u = new User();
        u.setName("Alice");
        u.setSurname("Jones");
        u.setEmail("alice.jones@test.it");
        u.setUsername(null);
        u.setPassword(bCryptPasswordEncoder.encode("HelloWorld!123"));
        u.setEnabled(true);
        assertThrows(DataIntegrityViolationException.class, () -> userRepository.save(u));
    }

    @Test
    public void testNullPassword() {
        User u = new User();
        u.setName("Alice");
        u.setSurname("Jones");
        u.setEmail("alice.jones@test.it");
        u.setUsername("username");
        u.setPassword(null);
        u.setEnabled(true);
        assertThrows(DataIntegrityViolationException.class, () -> userRepository.save(u));
    }
    
    @Test
    public void testNullEnabled() {
        User u = new User();
        u.setName("Alice");
        u.setSurname("Jones");
        u.setEmail("alice.jones@test.it");
        u.setUsername("username");
        u.setPassword(bCryptPasswordEncoder.encode("HelloWorld!123"));
        u.setEnabled(null);
        assertThrows(DataIntegrityViolationException.class, () -> userRepository.save(u));
    }
}
