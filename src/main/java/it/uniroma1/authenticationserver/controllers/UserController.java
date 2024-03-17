package it.uniroma1.authenticationserver.controllers;


import it.uniroma1.authenticationserver.entities.User;
import it.uniroma1.authenticationserver.repositories.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class UserController {

    @PostMapping("/users")
    @PreAuthorize("hasAnyRole('ROLE_AUTHORITIES', 'ROLE_SECURITY_ADMINISTRATOR')")
    public ResponseEntity<String> insertUser(@RequestBody User user) {
        // Check if all fields are not null or empty
        if (user == null || user.getUsername() == null || user.getUsername().isEmpty() ||
                user.getPassword() == null || user.getPassword().isEmpty() ||
                user.getEmail() == null || user.getEmail().isEmpty() ||
                user.getName() == null || user.getName().isEmpty() ||
                user.getSurname() == null || user.getSurname().isEmpty() ||
                user.getAuthorities() == null || user.getAuthorities().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("All fields must not be null or empty");
        }

        // Validate email format
        if (!user.getEmail().matches("^[A-Za-z0-9+_.-]+@(.+)$")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid email format");
        }

        // Perform insertion logic here
        if (isInsertionSuccessful(user)) {
            mockup(); // Call mockup function
            return ResponseEntity.ok("User inserted successfully");
        } else {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to insert user");
        }
    }

    private boolean isInsertionSuccessful(User user) {
        try {
            // Assuming userRepository is autowired into this class
            //userRepository.save(user); // Save the user to the database
            return true; // Return true if insertion is successful
        } catch (Exception e) {
            e.printStackTrace();
            return false; // Return false if insertion fails
        }
    }



    private boolean isUserValid(User user) {
        // Check if the user already exists in the database (pseudocode)
        UserRepository userRepository = null;
        User existingUserByEmail = userRepository.findByEmail(user.getEmail());
        if (existingUserByEmail != null) {
            return false; // Email already exists
        }

        User existingUserByUsername = userRepository.findByUsername(user.getUsername());
        if (existingUserByUsername != null) {
            return false; // Username already exists
        }

        // Validate password strength (pseudo code)
        if (!isStrongPassword(user.getPassword())) {
            return false; // Weak password
        }

        // Additional custom validation logic can be added here

        return true; // All validation checks passed
    }

    private boolean isStrongPassword(String password) {
        // Implement your password strength validation logic here
        // For example, check length, complexity, etc.
        return password.length() >= 8 && containsSpecialCharacter(password) && containsDigit(password);
    }

    private boolean containsSpecialCharacter(String str) {
        // Implement logic to check if the string contains special characters
        return str.matches(".*[!@#$%^&*()-+=<>?].*");
    }

    private boolean containsDigit(String str) {
        // Implement logic to check if the string contains digits
        return str.matches(".*\\d.*");
    }


    private void mockup() {
        System.out.println("Change Me!"); // Placeholder for actual implementation
    }
}


