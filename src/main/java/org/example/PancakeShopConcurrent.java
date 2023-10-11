package org.example;

import java.util.Random;

public class PancakeShopConcurrent {
    public static void main(String[] args) {
        int totalPancakesMade = 0;
        int totalPancakesEaten = 0;
        int totalUnmetOrders = 0;

        // Simulate two 30-second slots
        for (int slot = 1; slot <= 2; slot++) {
            System.out.println("=== Slot " + slot + " ===");

            int pancakesMade = new Random().nextInt(13); // Max 12 pancakes per slot
            int[] pancakesPerUser = generatePancakesForUsers();

            totalPancakesEaten = calculateTotalPancakesEaten(pancakesPerUser);

            System.out.println("Pancakes made by the shopkeeper: " + pancakesMade);
            System.out.println("Pancakes eaten by users: " + totalPancakesEaten);

            if (pancakesMade < totalPancakesEaten) {
                totalUnmetOrders += (totalPancakesEaten - pancakesMade);
                System.out.println("Shopkeeper couldn't meet all orders.");
                System.out.println("Unmet orders: " + (totalPancakesEaten - pancakesMade));
            } else {
                System.out.println("Shopkeeper met all orders.");
            }

            totalPancakesMade += pancakesMade;
        }
        System.out.println("\nTotal Pancakes Made: " + totalPancakesMade);
        System.out.println("Total Unmet Orders: " + totalUnmetOrders);
    }

    private static int[] generatePancakesForUsers() {
        int[] pancakesPerUser = new int[3];

        for (int user = 0; user < 3; user++) {
            pancakesPerUser[user] = new Random().nextInt(6); // Max 5 pancakes per user
        }

        return pancakesPerUser;
    }

    private static int calculateTotalPancakesEaten(int[] pancakesPerUser) {
        int total = 0;
        for (int user : pancakesPerUser) {
            total += user;
        }
        return total;
    }

    }
//    compare and contrast both versions of the code and highlight the observations:
//
//        Non-Concurrent Version:
//
//        Sequential Execution: In the non-concurrent version, all tasks are executed sequentially. The shopkeeper makes pancakes, and then the users eat pancakes one by one.
//
//        Random Generation: Random numbers for pancakes made and eaten are generated inside the loop for each slot.
//
//        Simple and Linear: The code is straightforward and linear, making it easy to follow without much complexity.
//
//        Single-Threaded: This version operates in a single thread, and there is no explicit concurrency management.
//
//        Limited Scalability: It may not efficiently handle a large number of users or more complex scenarios due to its sequential nature.
//
//        Concurrent Version (Without Threads or ExecutorServices):
//
//        Sequential Execution with Structure: Like the non-concurrent version, this version also executes tasks sequentially. However, it uses structured methods to generate user orders and calculate the total pancakes eaten.
//
//        Better Organization: The code is better organized with the use of helper methods, making it more readable and maintainable.
//
//        Encapsulation: The functionality for generating user orders and calculating the total pancakes eaten is encapsulated within methods, promoting better code encapsulation and reusability.
//
//        Improved Scalability: While still sequential, this version can handle a larger number of users or more complex scenarios more efficiently due to its structured approach.
//
//        Easier Maintenance: The structured approach makes it easier to maintain and extend the code in the future.
//
//        Overall Observations:
//
//        Both versions are simple and can handle the described scenario effectively.
//        The non-concurrent version is suitable for basic scenarios with limited users and simple logic.
//        The concurrent version, while still sequential, provides better organization and scalability, making it more suitable for larger-scale scenarios.
//        In real-world scenarios with more complex requirements and larger user bases, proper concurrency management using Threads or ExecutorServices is typically recommended for efficient parallel task execution. However, in the absence of those, the structured approach in the concurrent version can help improve code maintainability.

