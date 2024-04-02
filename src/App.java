import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class App {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        int option = 0;
        while (option != 9) {
            meniuOptions();
            option = scanner.nextInt();
            scanner.nextLine();
            switch (option) {
                case 1:
                    encodingRSA(scanner);
                    break;
                case 2:
                    decodingRSA();
                    break;
                case 9:
                System.out.println("Program closed!");
                    break;
                default:
                System.out.println("This is no option like this");
                    break;
            }
        }
    }

    public static void meniuOptions() {
        System.out.println("Pick one of the options: ");
        System.out.println("1. Encode with RSA");
        System.out.println("2. Decode RSA from text file");
        System.out.println("9. End program");
    }

    public static void encodingRSA(Scanner scanner) {
        System.out.println("Encoding...");
        System.out.println("Input first primary number: ");
        BigInteger p = scanner.nextBigInteger();
        scanner.nextLine();
        System.out.println("Input second primary number: ");
        BigInteger q = scanner.nextBigInteger();
        scanner.nextLine();
        System.out.println("Input text you want to encode: ");
        String text = scanner.nextLine();

        BigInteger n = p.multiply(q);
        BigInteger f = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger e = choosePublicExponent(f);
        BigInteger d = getPrivateKey(e, f);
        int[] encryptedText = encryptText(text, n, e);

        try (BufferedWriter writer = new BufferedWriter(new FileWriter("rsaEncrypted.txt"))) {
            writer.write("Encrypted Text: " + Arrays.toString(encryptedText));
            writer.newLine();
            writer.write("Public Key: " + n + "," + e);
            System.out.println("Encrypted text and public key saved");
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public static BigInteger choosePublicExponent(BigInteger f) {
        BigInteger e;
        do {
            e = getRandomPrime(f);
        } while (e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(f) >= 0 || euclideanAlgorithm(e, f).compareTo(BigInteger.ONE) != 0);
        return e;
    }

    public static BigInteger getRandomPrime(BigInteger upperBound) {
        Random random = new Random();
        BigInteger primeCandidate;
        do {
            primeCandidate = new BigInteger(upperBound.bitLength(), random).mod(upperBound.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        } while (!isPrime(primeCandidate));
        return primeCandidate;
    }

    public static boolean isPrime(BigInteger n) {
        if (n.compareTo(BigInteger.ONE) <= 0) {
            return false;
        }
        if (n.compareTo(BigInteger.valueOf(3)) <= 0) {
            return true;
        }
        if (n.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO) || n.mod(BigInteger.valueOf(3)).equals(BigInteger.ZERO)) {
            return false;
        }
        BigInteger i = BigInteger.valueOf(5);
        while (i.multiply(i).compareTo(n) <= 0) {
            if (n.mod(i).equals(BigInteger.ZERO) || n.mod(i.add(BigInteger.valueOf(2))).equals(BigInteger.ZERO)) {
                return false;
            }
            i = i.add(BigInteger.valueOf(6));
        }
        return true;
    }

    public static BigInteger euclideanAlgorithm(BigInteger e, BigInteger f) {
        while (!f.equals(BigInteger.ZERO)) {
            BigInteger temp = f;
            f = e.mod(f);
            e = temp;
        }
        return e;
    }

    public static BigInteger[] extendedEuclideanAlgorithm(BigInteger e, BigInteger f) {
        BigInteger a = BigInteger.ZERO, b = BigInteger.ONE, last1 = BigInteger.ONE, last2 = BigInteger.ZERO, check1 = e, check2 = f;
        while (!f.equals(BigInteger.ZERO)) {
            BigInteger quotient = e.divide(f);
            BigInteger remainder = e.mod(f);

            e = f;
            f = remainder;

            BigInteger temp = a;
            a = last1.subtract(quotient.multiply(a));
            last1 = temp;
            temp = b;
            b = last2.subtract(quotient.multiply(b));
            last2 = temp;
        }
        if (last1.multiply(check1).add(last2.multiply(check2)).equals(e)) {
        }
        return new BigInteger[]{last1, last2, e};
    }

    public static BigInteger getPrivateKey(BigInteger e, BigInteger f) {
        BigInteger[] extended = extendedEuclideanAlgorithm(e, f);
        BigInteger x = extended[0];
        BigInteger gcdCheck = extended[2];
        if (!gcdCheck.equals(BigInteger.ONE)) {
            throw new IllegalArgumentException("e and f are not coprime");
        }
        BigInteger d = x.mod(f);
        while (d.compareTo(BigInteger.ZERO) < 0) {
            d = d.add(f);
        }
        return d;
    }

    public static int[] encryptText(String text, BigInteger n, BigInteger e) {
        byte[] bytes = text.getBytes();
        int[] encryptedMessage = new int[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            int textByte = bytes[i];
            encryptedMessage[i] = BigInteger.valueOf(textByte).modPow(e, n).intValue();
        }
        return encryptedMessage;
    }

    public static void decodingRSA() {
        System.out.println("Decoding...");
        BigInteger[] publicKey = readPublicKey();
        int[] encryptedText = readEncryptedText();
        BigInteger n = publicKey[0];
        BigInteger e = publicKey[1];
        BigInteger p = getPrimeNumber(n);
        BigInteger q = n.divide(p);
        BigInteger f = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger d = getPrivateKey(e, f);
        String text = decodeRSA(encryptedText, d, n);
        System.out.println("Decoded RSA text from file: " + text);
    }

    public static BigInteger[] readPublicKey() {
        BigInteger[] publicKey = new BigInteger[2];
        try {
            File file = new File("rsaEncrypted.txt");
            FileReader fileReader = new FileReader(file);
            BufferedReader reader = new BufferedReader(fileReader);
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("Public Key:")) {
                    String[] parts = line.split(":")[1].trim().split(",");
                    publicKey[0] = new BigInteger(parts[0].trim());
                    publicKey[1] = new BigInteger(parts[1].trim());
                }
            }
            reader.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return publicKey;
    }
    
    public static int[] readEncryptedText() {
        int[] encryptedText = null;
        try (BufferedReader reader = new BufferedReader(new FileReader("rsaEncrypted.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("Encrypted Text:")) {
                    String[] parts = line.split(":")[1].trim().replaceAll("[\\[\\]]", "").split(",");
                    encryptedText = new int[parts.length];
                    for (int i = 0; i < parts.length; i++) {
                        encryptedText[i] = Integer.parseInt(parts[i].trim());
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return encryptedText;
    }
    
    public static BigInteger getPrimeNumber(BigInteger n) {
        BigInteger i = BigInteger.valueOf(2);
        while (i.multiply(i).compareTo(n) <= 0) {
            if (n.remainder(i).equals(BigInteger.ZERO)) {
                return i;
            }
            i = i.add(BigInteger.ONE);
        }
        return n;
    }

    public static String decodeRSA(int[] encryptedText, BigInteger d, BigInteger n) {
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < encryptedText.length; i++) {
            BigInteger textByte = BigInteger.valueOf(encryptedText[i]).modPow(d, n);
            text.append((char) textByte.intValue());
        }
        return text.toString();
    }
}