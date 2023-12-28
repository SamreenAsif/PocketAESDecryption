
import java.util.Scanner;
import java.util.HashMap;

public class PocketAESDecryption {
    public static void main(String[] args) {
//       takes two inputs of 16 bits each — a ciphertext and key.
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter the ciphertext block: ");
        String cipherText = scanner.nextLine();
        System.out.print("Enter key for decryption: ");
        String key = scanner.nextLine() ;
        // Validate the master key length.
        while (key.length() < 4) {
            key = "0" + key; // Ensure 4-digit hexadecimal representation
        }
        String decipher = applyDecryption(cipherText ,key);
        System.out.println("Decrypted Block :" + (decipher));

    }

    private static String applyDecryption(String cipherText, String key) {

        System.out.println("Key: " + key) ;
        String roundKey1 = generateRoundKey(key, 0x1110 );
        String roundKey2 = generateRoundKey(roundKey1, 0x1010);

        // Display the round keys in hexadecimal format.
        System.out.println("Round Key 1: " + roundKey1);
        System.out.println("Round Key 2: " + roundKey2);


        String round1Decipher = decipher(cipherText,roundKey2, 1);
        System.out.println("After round 1 : " +round1Decipher);
        String round2Decipher = decipher((round1Decipher ), roundKey1 ,2) ;

        return round2Decipher ;

    }

    private static String decipher(String cipherText, String key, int roundCount) {

        //Step 1 shift row
        String decryptedText = shiftRow(cipherText);
        System.out.println("Shift Rows : " + decryptedText);

        //Step 4  mix col(only in round 2)
        if (roundCount == 2) {

            int[] inverseMatrix = {0x9, 0x2, 0x2, 0x9}; // Constant matrix for inverse MixColumns
            decryptedText = mixColumn(decryptedText, inverseMatrix);
            System.out.println("Mix colmuns : " + decryptedText);
        }
        // Step 2 add round key (for round 1 add k2)
        decryptedText = binaryToHex(binaryXOR(hexToBinary(key) , hexToBinary(decryptedText)));
        System.out.println("Add round key : " + decryptedText);

        // Step 3 find subnibbles
        decryptedText = reverseSubNibbles(hexToBinary(decryptedText)) ;
        System.out.println("Subnibbles : " +  binaryToHex(decryptedText));


        return binaryToHex(decryptedText) ;


    }

    // Convert hexadecimal to binary.
    public static String hexToBinary(String hexadecimal) {
        String binary = "";
        for (int i = 0; i < hexadecimal.length(); i++) {
            char hexChar = hexadecimal.charAt(i);
            int hexValue = Character.digit(hexChar, 16);
            String binaryPart = Integer.toBinaryString(hexValue);
            while (binaryPart.length() < 4) {
                binaryPart = "0" + binaryPart; // Ensure 4-digit binary representation
            }
            binary += binaryPart;
        }
        return binary;
    }

    public static String binaryToHex(String binaryInput) {
        int decimal = Integer.parseInt(binaryInput, 2);

        String res = Integer.toHexString(decimal).toUpperCase();
        if (binaryInput.length() == 16 && res.length() < 4) {
            // Add leading zeros if the result is less than 4 characters long
            while (res.length() < 4) {
                res = "0" + res;
            }
        }

        return res;

    }

    // Substitution table for the SubNibbles stage (binary-to-binary).
    private static final HashMap<String, String> substitutionTable = new HashMap<String, String>() {{
        put("0000", "1010");
        put("0001", "0000");
        put("0010", "1001");
        put("0011", "1110");
        put("0100", "0110");
        put("0101", "0011");
        put("0110", "1111");
        put("0111", "0101");
        put("1000", "0001");
        put("1001", "1101");
        put("1010", "1100");
        put("1011", "0111");
        put("1100", "1011");
        put("1101", "0100");
        put("1110", "0010");
        put("1111", "1000");
    }};

    // Step 1: SubNibbles
    private static String subNibbles(String binaryText) {
//        String binaryText = hexToBinary(text);
        StringBuilder substituted_text = new StringBuilder();

        // Iterate over the binary input in 4-bit chunks and apply SubNibbles.
        for (int i = 0; i < binaryText.length(); i += 4) {
            String nibble = binaryText.substring(i, i + 4);
            if (substitutionTable.containsKey(nibble)) {
                substituted_text.append(substitutionTable.get(nibble));
            } else {
                throw new IllegalArgumentException("Invalid binary nibble: " + nibble);
            }
        }

        return substituted_text.toString();

    }

    // Step 2 : ShiftRow
    private static String shiftRow(String plaintext) {
        if (plaintext.length() != 4) {
            throw new IllegalArgumentException("Input must be a 4-character hexadecimal string.");
        }

        // Swap the positions of the first and second nibbles.
        char nibble0 = plaintext.charAt(0);
        char nibble1 = plaintext.charAt(1);

        // Keep the third and fourth nibbles in their positions.
        char nibble2 = plaintext.charAt(2);
        char nibble3 = plaintext.charAt(3);

        // Form the shifted hexadecimal string.
        String shiftedHex = "" + nibble2 + nibble1 + nibble0 + nibble3;

        return shiftedHex;
    }

    //Step 3 : Mix Columns
    private static String mixColumn(String plaintext, int[] constantMatrix) {

        // Split the hexadecimal string into two halves
        String leftHalf = plaintext.substring(0, 2);
        String rightHalf = plaintext.substring(2);

        // Apply MixColumns operation to each half separately
        String mixedLeftHalf = mixColumnHalf(leftHalf, constantMatrix);
        String mixedRightHalf = mixColumnHalf(rightHalf, constantMatrix);

        // Combine the two halves to get the final mixed result
        return mixedLeftHalf + mixedRightHalf;
    }

    private static String mixColumnHalf(String hexHalf, int[] constantMatrix) {

        int[] hexValues = new int[2];

        // Convert the hexadecimal half to integer values
        for (int i = 0; i < 2; i++) {
            char hexChar = hexHalf.charAt(i);
            hexValues[i] = Integer.parseInt(String.valueOf(hexChar), 16);
        }

        // Apply MixColumns operation using the constant matrix
        int mixedValue1 = multiplyInGF2_4(constantMatrix[0], hexValues[0]) ^ multiplyInGF2_4(constantMatrix[1], hexValues[1]);
        int mixedValue2 = multiplyInGF2_4(constantMatrix[2], hexValues[0]) ^ multiplyInGF2_4(constantMatrix[3], hexValues[1]);

        // Convert the mixed values back to hexadecimal
        String mixedHex1 = Integer.toHexString(mixedValue1);
        String mixedHex2 = Integer.toHexString(mixedValue2);


        // Combine the two mixed hexadecimal values
        return mixedHex1 + mixedHex2;
    }

    // Multiplication in GF(2^4)
    static int multiplyInGF2_4(int a, int b) {
        int m = 0;
        while (b > 0) {
            if ((b & 1) == 1) {
                m ^= a;
            }
            boolean fourthBitSet = (a & 0b1000) != 0;
            a <<= 1;
            if (fourthBitSet) {
                a ^= 0b10011; // The irreducible polynomial x^4 + x + 1
            }
            b >>= 1;
        }
        return m & 0b1111; // Reduce to 4 bits (GF(2^4) modulo)
    }

    // Generate round Keys
    // Generate a round key based on the master key, round constant, and round number.
    private static String generateRoundKey(String masterKey, int rCon1) {
        // Convert the master key to binary.
        System.out.println("Inside generate round key");
        String masterKeyBinary = hexToBinary(masterKey);

        // Split the master key into nibbles.
        String w0 = masterKeyBinary.substring(0, 4);
        String w1 = masterKeyBinary.substring(4, 8);
        String w2 = masterKeyBinary.substring(8, 12);
        String w3 = masterKeyBinary.substring(12);

        // Apply SubNibbles to the last nibble and XOR with round constant.
        String w3SubNibbles = subNibbles(w3);

        String roundConstantHex = Integer.toHexString(rCon1);

        while (roundConstantHex.length() < 4) {
            roundConstantHex = "0" + roundConstantHex; // Ensure 4-digit hexadecimal representation
        }

        String w4 = (binaryXOR((w3SubNibbles), (roundConstantHex)));

        String w41 = (binaryXOR(w0, w4));

        // XOR w1 with w4 to get w5.
        String w5 = (binaryXOR((w1), (w41)));

        // XOR w2 with w5 to get w6.
        String w6 = (binaryXOR((w2), (w5)));

        // XOR w3 with w6 to get w7.
        String w7 = (binaryXOR((w3), (w6)));

        // Combine the nibbles to form the round key.
        String roundKey = binaryToHex(w41) + binaryToHex(w5) + binaryToHex(w6) + binaryToHex(w7);

        return roundKey;
    }

    // Perform binary XOR between two binary strings of equal length.
    private static String binaryXOR(String binary1, String binary2) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < binary1.length(); i++) {
            result.append(binary1.charAt(i) ^ binary2.charAt(i));
        }
        return result.toString();
    }


    // Step 1: Reverse SubNibbles (apply inverse substitution)
    private static String reverseSubNibbles(String binaryInput) {
        StringBuilder reversedText = new StringBuilder();

        // Iterate over the binary input in 4-bit chunks and apply the inverse SubNibbles.
        for (int i = 0; i < binaryInput.length(); i += 4) {
            String nibble = binaryInput.substring(i, i + 4);
            String reversedNibble = reverseSubstitution(nibble);
            reversedText.append(reversedNibble);
        }

        return reversedText.toString();
    }

    // Function to reverse the substitution (inverse SubNibbles)
    private static String reverseSubstitution(String nibble) {
        for (String key : substitutionTable.keySet()) {
            if (substitutionTable.get(key).equals(nibble)) {
                return key;
            }
        }
        throw new IllegalArgumentException("Invalid binary nibble: " + nibble);
    }


}