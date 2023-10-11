package org.example;

import java.util.Random;

public class PancakeShopNonConcurrent {
        public static void main(String[] args) {
            int totalPancakesMade = 0;
            int totalPancakesEaten = 0;
            int totalUnmetOrders = 0;

            // Simulate two 30-second slots
            for (int slot = 1; slot <= 2; slot++) {
                System.out.println("=== Slot " + slot + " ===");

                int pancakesMade = new Random().nextInt(13);
                int[] pancakesPerUser = new int[3];

                for (int user = 0; user < 3; user++) {
                    pancakesPerUser[user] = new Random().nextInt(6);
                    totalPancakesEaten += pancakesPerUser[user];
                }

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
                totalPancakesEaten = 0;
            }

            System.out.println("\nTotal Pancakes Made: " + totalPancakesMade);
            System.out.println("Total Unmet Orders: " + totalUnmetOrders);
        }
    }



