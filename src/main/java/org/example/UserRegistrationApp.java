package org.example;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;


public class UserRegistrationApp {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Collect user input
        System.out.print("Enter Username (minimum 4 characters): ");
        String username = scanner.nextLine();

        System.out.print("Enter Email: ");
        String email = scanner.nextLine();

        System.out.print("Enter Password (minimum 8 characters, at least 1 upper case, 1 special character, 1 number): ");
        String password = scanner.nextLine();

        System.out.print("Enter Date of Birth (yyyy-MM-dd): ");
        String dobStr = scanner.nextLine();

        scanner.close();

        // Perform validations concurrently
        CompletableFuture<Boolean> usernameValidation = validateUsername(username);
        CompletableFuture<Boolean> emailValidation = validateEmail(email);
        CompletableFuture<Boolean> passwordValidation = validatePassword(password);
        CompletableFuture<Boolean> dobValidation = validateDOB(dobStr);

        // Wait for all validations to complete
        CompletableFuture<Void> allOf = CompletableFuture.allOf(
                usernameValidation, emailValidation, passwordValidation, dobValidation);

        try {
            allOf.get(); // Wait for all validations to complete
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
        // Check results and display messages
        if (usernameValidation.join() && emailValidation.join() && passwordValidation.join() && dobValidation.join()) {
            String jwt = generateJWT(username);
            System.out.println("Registration Successful!");
            System.out.println("JWT Token: " + jwt);
        } else {
            System.out.println("Validation Failed. Please check the following:");

            if (!usernameValidation.join()) {
                System.out.println("Username: minimum 4 characters required.");
            }
            if (!emailValidation.join()) {
                System.out.println("Email: not a valid email address.");
            }
            if (!passwordValidation.join()) {
                System.out.println("Password: not a strong password.");
            }
            if (!dobValidation.join()) {
                System.out.println("Date of Birth: should be 16 years or greater.");
            }
        }
    }

    // Validation methods (asynchronous)
    private static CompletableFuture<Boolean> validateUsername(String username) {
        return CompletableFuture.supplyAsync(() -> username.length() >= 4);
    }
    private static CompletableFuture<Boolean> validateEmail(String email) {
        return CompletableFuture.supplyAsync(() -> isValidEmail(email));
    }

    private static CompletableFuture<Boolean> validatePassword(String password) {
        return CompletableFuture.supplyAsync(() -> isStrongPassword(password));
    }

    private static CompletableFuture<Boolean> validateDOB(String dobStr) {
        return CompletableFuture.supplyAsync(() -> {
            LocalDate dob = parseDateOfBirth(dobStr);
            return dob != null && isValidDOB(dob);
        });
    }

    // Email validation using regex
    private static boolean isValidEmail(String email) {
        String regex = "^[A-Za-z0-9+_.-]+@(.+)$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(email);
        return matcher.matches();
    }

    // Password validation using regex
    private static boolean isStrongPassword(String password) {
        String regex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])(?=\\S+$).{8,}$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(password);
        return matcher.matches();
    }

    // Date of Birth validation (16 years or greater)
    private static boolean isValidDOB(LocalDate dob) {
        LocalDate currentDate = LocalDate.now();
        LocalDate sixteenYearsAgo = currentDate.minusYears(16);
        return dob.isBefore(sixteenYearsAgo);
    }

    // Parse Date of Birth string to LocalDate
    private static LocalDate parseDateOfBirth(String dobStr) {
        try {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
            return LocalDate.parse(dobStr, formatter);
        } catch (Exception e) {
            return null;
        }
    }

    // Generate a JWT
    private static String generateJWT(String username) {
        String secretKey = "Base64.getEncoder().encodeToString(keyBytes)Gabs";

        return Jwts.builder()
                .setSubject(username)
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()), SignatureAlgorithm.HS256)
                .compact();

    }
    // Verify the JWT token
    private static String verifyToken(String jwtToken) {
        try {
            byte[] keyBytes = Keys.secretKeyFor(SignatureAlgorithm.HS256).getEncoded();
            String secretKey = Base64.getEncoder().encodeToString(keyBytes);
            // Parse and verify the JWT token
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes()))
                    .build()
                    .parseClaimsJws(jwtToken)
                    .getBody();

            // If verification succeeds, return "verification pass"
            return "verification pass";
        } catch (ExpiredJwtException e) {
            return "verification fails: token has expired";
        } catch (Exception e) {
            return "verification fails";
        }
    }
}


